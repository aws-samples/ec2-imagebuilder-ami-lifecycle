#!/usr/bin/env python

"""
    ami_creation_lifecycle_post.py: 
    lambda handler for the ami creation post url:
    POST: https://{api_endpoint}/ami-creation/lifecycles
    See OpenAPI specification (ami-orchestrator-api.yaml) for more details.
"""

import json
import logging
import os
import traceback

from .services.aws_api_service import AwsApiService
from .services.cloudformation_service import CloudformationService
from .services.constants_service import ConstantsService
from .services.database_service import DatabaseService
from .services.notifier_service import NotifierService
from .services.orchestrator_service import OrchestratorService
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

# static variable delcarations
OPERATOR = "AMI_CREATION_POST"
TEMPLATE_FILE = "lifecycle_event_notification.template"
ERROR_TEMPLATE_FILE = "lifecycle_event_notification_error.template"

def lambda_handler(event, context):
    # read the event to json
    logger.debug(json.dumps(event, indent=2))

    try:

        logger.debug(json.loads(event['body']))

        statemachine_export = os.environ['AMI_BUILD_STATEMACHINE_NAME']
        imagebuilder_pipeline_export = os.environ['IMAGEBUILDER_PIPELINE_ARN']
        
        lifecycle_request = json.loads(event['body'])

        # validate the API key
        if 'api_key' not in lifecycle_request:
            raise ValueError(f"An api_key must be included as part of the json payload of the request.")
        
        # if the api_key is not valid an exception will be raised
        security_service.is_ami_creation_post_authorized(lifecycle_request['api_key'])

        # validate the structure and basic logic of request 
        # if the request is not valid a ValidationError exception will be raised
        validator_service.validate_lifecycle_definition_create_request(lifecycle_request)

        # write the job definition to dynamodb
        lifecycle_obj = database_service.create_lifecycle(lifecycle_request)

        # subscribe email notification channels to the SNS topic
        if 'notifications' in lifecycle_obj:
            for notification in lifecycle_obj['notifications']:
                if notification['method'] == "EMAIL":
                    notifier_service.create_email_subscription("email", notification['target'], lifecycle_obj['lifecycle_id'])

        # subscribe event_notification lambda to the lifecycle
        notifier_service.create_lambda_subscription(
            lifecycle_id=lifecycle_obj['lifecycle_id']
        )

        # grab the iamgebuilder arn from cloudformation export
        imagebuilder_arn = cloudformation_service.get_stack_output_value(
            cfn_stack_name=constants_service.CLOUDFORMATION_STACK_IMAGEBUILDER,
            output_name=imagebuilder_pipeline_export
        )

        # define the state machine input for ami build
        state_machine_input = {
            "imagebuilder_pipeline_arn": imagebuilder_arn,
            "lifecycle_id": lifecycle_obj['lifecycle_id'],
            "api_endpoint": awsapi_service.get_base_endpoint(),
            "product_ver": lifecycle_request['product_ver'],
            "product_name": lifecycle_request['product_name'],
            "commit_ref": lifecycle_request['commit_ref'],
            "cfn_stack_name": lifecycle_obj['stack_tag']
        }

        formatted_state_machine_input = statemachine_service.generate_state_machine_input(
                                    state_machine_input = state_machine_input
                                )

        properties = {
            "imagebuilder_pipeline_arn": imagebuilder_arn,
            "product_ver": lifecycle_request['product_ver'],
            "product_name": lifecycle_request['product_name'],
            "commit_ref": lifecycle_request['commit_ref']
        }

        orchestrator_service.execute_state_machine(
            statemachine_input=formatted_state_machine_input,
            statemachine_export_name=statemachine_export,
            definition=lifecycle_obj,
            event_name=constants_service.EVENT_BUILD_AMI,
            event_description=constants_service.EVENT_BUILD_AMI_DESCRIPTION,
            event_properties=properties
        )

        # send the notification
        notifier_service.send_event_notification(
            operator=OPERATOR,
            definition=lifecycle_obj,
            template_file=TEMPLATE_FILE
        )
        

        response = {
            "lifecycle_id": lifecycle_obj['lifecycle_id'],
            "owner": lifecycle_obj['owner'],
            "creation_date": lifecycle_obj['creation_date'],
            "notification_channels": lifecycle_obj['notifications']
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
            lifecycle_obj
        except NameError:
            # lifecycle_definition is not defined
            template_attributes['lifecycle_id'] = "NOT_CREATED"
            template_attributes['status_url'] = "NOT_AVAILABLE"
        else:
            # lifecycle_definition is defined
            template_attributes['lifecycle_id'] = lifecycle_obj['lifecycle_id']
            template_attributes['status_url'] = awsapi_service.get_ami_status_endpoint(lifecycle_obj['lifecycle_id'])
            
        template_attributes['stack_tag'] = lifecycle_request['stack_tag']
        template_attributes['error'] = api_error

        subject = f"ERROR in {OPERATOR} event for {lifecycle_request['stack_tag']}"

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
