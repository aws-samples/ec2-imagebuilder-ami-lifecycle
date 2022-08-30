#!/usr/bin/env python

"""
    ami_patch_lifecycle_put.py: 
    lambda handler for the ami patch put url:
    PUT: https://{api_endpoint}/ami-patch/lifecycles
    See OpenAPI specification (ami-orchestrator-api.yaml) for more details.
"""

import json
import logging
import traceback

from .services.ami_details_service import AmiDetailsService
from .services.aws_api_service import AwsApiService
from .services.constants_service import ConstantsService
from .services.database_service import DatabaseService
from .services.notifier_service import NotifierService
from .services.orchestrator_service import OrchestratorService
from .services.rules_service import RulesService
from .services.security_service import SecurityService
from .services.validator_service import ValidatorService

# set logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

database_service = DatabaseService()
validator_service = ValidatorService()
notifier_service = NotifierService()
awsapi_service = AwsApiService()
security_service = SecurityService()
orchestrator_service = OrchestratorService()
constants_service = ConstantsService()
ami_details_service = AmiDetailsService()
rules_service = RulesService()

# static variable delcarations
OPERATOR = "AMI_PATCH_PUT"
TEMPLATE_FILE = "lifecycle_event_notification.template"
ERROR_TEMPLATE_FILE = "lifecycle_event_notification_error.template"

def lambda_handler(event, context):
    # read the event to json
    logger.debug(json.dumps(event, indent=2))

    try:

        logger.debug(json.loads(event['body']))
        
        definition = json.loads(event['body'])

        # validate the API key
        if 'api_key' not in definition:
            raise ValueError(f"An api_key must be included as part of the json payload of the request.")
        
        # if the api_key is not valid an exception will be raised
        security_service.is_ami_patch_put_authorized(definition['api_key'])

        # validate the structure and basic logic of request 
        # if the request is not valid a ValidationError exception will be raised
        validator_service.validate_lifecycle_definition_patch_request(
            definition=definition,
            isPost=False
        )

        # perform a sanity check to ensure that patching can proceed
        rules_service.validate_patching_prerequisites(
            definition=database_service.get_lifecycle_by_lifecycle_id(definition['lifecycle_id'])
        )

        # write the job definition to dynamodb
        lifecycle_defintion = database_service.patch_create_update_lifecycle(definition)

        # dispatch next event action to the orchestrator service
        orchestrator_service.handle_next_event(
            api_type=constants_service.AMI_PATCH,
            definition=database_service.get_lifecycle_by_lifecycle_id(lifecycle_defintion['lifecycle_id'])
        )

        # send the notification
        notifier_service.send_event_notification(
            operator=OPERATOR,
            definition=lifecycle_defintion,
            template_file=TEMPLATE_FILE
        )

        notification_channels = []

        for notification in lifecycle_defintion['notifications']:
            notification_channels.append({
                "method": notification['method'],
                "target": notification['target']
            })

        response = {
            "lifecycle_id": lifecycle_defintion['lifecycle_id'],
            "owner": lifecycle_defintion['owner'],
            "creation_date": lifecycle_defintion['inputs_ami_patch']['update_date'],
            "notification_channels": notification_channels
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
            definition
        except NameError:
            # definition is not defined
            template_attributes['lifecycle_id'] = "UNDEFINED"
            template_attributes['stack_tag'] = "UNDEFINED"
            template_attributes['status_url'] = "UNDEFINED"
        else:
            # definition is defined
            if "lifecycle_id" in definition:
                template_attributes['lifecycle_id'] = definition['lifecycle_id']
                template_attributes['status_url'] = awsapi_service.get_ami_status_endpoint(definition['lifecycle_id'])
            else:
                template_attributes['lifecycle_id'] = "UNDEFINED"
                template_attributes['status_url'] = "UNDEFINED"
            
            if "stack_tag" in definition:
                template_attributes['stack_tag'] = definition['stack_tag']
            else:
                template_attributes['stack_tag'] = "UNDEFINED"

        template_attributes['error'] = api_error

        subject = f"ERROR in {OPERATOR} event for {template_attributes['stack_tag']}"

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
