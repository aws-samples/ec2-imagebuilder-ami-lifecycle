#!/usr/bin/env python

"""
    ami_patch_lifecycle_post.py: 
    lambda handler for the ami patch post url:
    POST: https://{api_endpoint}/ami-patch/lifecycles
    See OpenAPI specification (ami-orchestrator-api.yaml) for more details.
"""

import datetime
import json
import logging
import os
import traceback

import boto3

from .services.ami_details_service import AmiDetailsService
from .services.aws_api_service import AwsApiService
from .services.cloudformation_service import CloudformationService
from .services.constants_service import ConstantsService
from .services.database_service import DatabaseService
from .services.notifier_service import NotifierService
from .services.orchestrator_service import OrchestratorService
from .services.rules_service import RulesService
from .services.s3_parser_service import S3ParserService
from .services.security_service import SecurityService
from .services.statemachine_service import StateMachineService
from .services.validator_service import ValidatorService

# set logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

database_service = DatabaseService()
validator_service = ValidatorService()
notifier_service = NotifierService()
awsapi_service = AwsApiService()
security_service = SecurityService()
statemachine_service = StateMachineService()
cloudformation_service = CloudformationService()
constants_service = ConstantsService()
orchestrator_service = OrchestratorService()
ami_details_service = AmiDetailsService()
rules_service = RulesService()

# static variable delcarations
OPERATOR = "AMI_PATCH_POST"
TEMPLATE_FILE = "lifecycle_event_notification.template"
ERROR_TEMPLATE_FILE = "lifecycle_event_notification_error.template"

# boto3 definitions
s3_client = boto3.client('s3')
s3_resource = boto3.resource('s3')

def lambda_handler(event, context):
    # read the event to json
    logger.debug(json.dumps(event, indent=2))

    try:

        logger.debug(json.loads(event['body']))

        statemachine_export = os.environ['AMI_PATCH_STATEMACHINE_NAME']
        
        definition = json.loads(event['body'])

        # validate the API key
        if 'api_key' not in definition:
            raise ValueError(f"An api_key must be included as part of the json payload of the request.")
        
        # if the api_key is not valid an exception will be raised
        security_service.is_ami_patch_post_authorized(definition['api_key'])

        # validate the structure and basic logic of request 
        # if the request is not valid a ValidationError exception will be raised
        validator_service.validate_lifecycle_definition_patch_request(
            definition=definition,
            isPost=True
        )

        # sanity check that patch component url contains a file
        patch_component_url = definition['properties']['patch_component_url']
        s3_parser_service = S3ParserService(patch_component_url)
        bucket = s3_parser_service.bucket
        object_key = s3_parser_service.key.lstrip('/')
        logger.debug(f"bucket: {bucket}, object_key: {object_key}")
        try:
            s3_resource.Object(bucket, object_key).load()
        except Exception as e:
            msg = (
                f"The specified patch_component_url, {patch_component_url}, " +
                "does not exist in S3. This is a mandatory attribute. Please verify the " +
                "location and existence of this file and try again. The specific error message "
                f"is: {str(e)}"
            )
            raise ValueError(msg)

        # perform a sanity check to ensure that patching can proceed
        rules_service.validate_patching_prerequisites(
            definition=database_service.get_lifecycle_by_lifecycle_id(definition['lifecycle_id'])
        )
        
        # write the job definition to dynamodb
        lifecycle_definition = database_service.patch_create_update_lifecycle(definition)

        # subscribe email notification channels to the SNS topic
        if 'notifications' in lifecycle_definition:
            for notification in lifecycle_definition['notifications']:
                if notification['method'] == "EMAIL":
                    notifier_service.create_email_subscription("email", notification['target'], lifecycle_definition['lifecycle_id'])

        # subscribe event_notification lambda to the lifecycle
        notifier_service.create_lambda_subscription(
            lifecycle_id=lifecycle_definition['lifecycle_id']
        )

        # set the sematic version based on date pattern
        current_day_hour_min_sec = (
            f"{datetime.datetime.now().strftime('%d')}" +
            f"{datetime.datetime.now().strftime('%H')}" +
            f"{datetime.datetime.now().strftime('%M')}" +
            f"{datetime.datetime.now().strftime('%S')}"
        )
        current_month = datetime.datetime.now().strftime('%m')
        current_year = datetime.datetime.now().strftime('%Y')
        semantic_version_dot = f"{current_year}.{current_month}.{current_day_hour_min_sec}"
        semantic_version_dash = f"{current_year}-{current_month}-{current_day_hour_min_sec}"

        ami_detail = ami_details_service.get_base_ami_details_for_patching(lifecycle_definition)

        # define the state machine input for ami patch
        state_machine_input = {
            "patch_component_url": patch_component_url,
            "patch_change_description": definition['properties']['patch_change_description'],
            "lifecycle_id": lifecycle_definition['lifecycle_id'],
            "semantic_version_dash": semantic_version_dash,
            "semantic_version_dot": semantic_version_dot,
            "ami_id": ami_detail['image'],
            "ami_name": ami_detail['name'],
            "ami_region": ami_detail['region'],
            "ami_owner": ami_detail['accountId'],
            "ami_semver": ami_detail['ami_semver'],
            "semver_bump_type": definition['properties']['semver_bump_type'],
            "cfn_stack_name": lifecycle_definition['stack_tag'],
            "commit_ref": definition['commit_ref']
        }

        formatted_state_machine_input = statemachine_service.generate_state_machine_input(
                                            state_machine_input = state_machine_input
                                        )

        properties = {
            "patch_component_url": patch_component_url,
            "patch_change_description": definition['properties']['patch_change_description'],
            "semantic_version_dash" : semantic_version_dash,
            "semantic_version_dot" : semantic_version_dot,
            "parent_ami_id": ami_detail['image'],
            "parent_ami_name": ami_detail['name'],
            "parent_ami_region":ami_detail['region'],
            "parent_ami_owner": ami_detail['accountId'],
            "parent_ami_semver": ami_detail['ami_semver'],
            "semver_bump_type": definition['properties']['semver_bump_type'],
            "commit_ref": definition['commit_ref']
        }

        orchestrator_service.execute_state_machine(
            statemachine_input=formatted_state_machine_input,
            statemachine_export_name=statemachine_export,
            definition=lifecycle_definition,
            event_name=constants_service.EVENT_PATCH_AMI,
            event_description=constants_service.EVENT_PATCH_AMI_DESCRIPTION,
            event_properties=properties
        )

        # send the notification
        notifier_service.send_event_notification(
            operator=OPERATOR,
            definition=lifecycle_definition,
            template_file=TEMPLATE_FILE
        )

        response = {
            "lifecycle_id": lifecycle_definition['lifecycle_id'],
            "owner": lifecycle_definition['owner'],
            "creation_date": lifecycle_definition['creation_date'],
            "notification_channels": lifecycle_definition['notifications']
        }

        return {
            'statusCode': 200,
            'body': json.dumps(response),
            'headers': {'Content-Type': 'application/json'}
        }
    
    except ValueError as e:
        logger.error(f'{OPERATOR} AMI Lifecycle error: {str(e)}')

        api_error = {"error": str(e)}

        return {
            'statusCode': 500,
            'body': json.dumps(api_error),
            'headers': {'Content-Type': 'application/json'}
        }

    except Exception as e:
        
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)

        logger.error(f'{OPERATOR} AMI Lifecycle error: {str(e)}')

        api_error = {"error": str(e)}

        # prepare the attributes for the message template
        template_attributes = {}
        template_attributes['operator'] = OPERATOR

        try:
            lifecycle_definition
        except NameError:
            # lifecycle_definition is not defined
            template_attributes['lifecycle_id'] = "NOT_CREATED"
            template_attributes['status_url'] = "NOT_AVAILABLE"
        else:
            # lifecycle_definition is defined
            template_attributes['lifecycle_id'] = lifecycle_definition['lifecycle_id']
            template_attributes['status_url'] = awsapi_service.get_ami_patch_status_endpoint(lifecycle_definition['lifecycle_id'])
            
        template_attributes['stack_tag'] = definition['stack_tag']
        template_attributes['error'] = api_error

        subject = f"ERROR in {OPERATOR} event for {definition['stack_tag']}"

        # send the notification
        notifier_service.send_notification(
            subject=subject, 
            template_name=ERROR_TEMPLATE_FILE, 
            template_attributes=template_attributes
        )

        return {
            'statusCode': 500,
            'body': json.dumps(api_error),
            'headers': {'Content-Type': 'application/json'}
        }
