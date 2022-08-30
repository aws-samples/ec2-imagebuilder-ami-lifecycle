#!/usr/bin/env python

"""
    ami_error_receiver.py: 
    a SQS receiver which responds to errors that occur
    during AMI Lifecycle AMI Creation and AMI Patch operations.
"""

import json
import logging
import traceback

import boto3

from ..services.ami_details_service import AmiDetailsService
from ..services.aws_api_service import AwsApiService
from ..services.constants_service import ConstantsService
from ..services.database_service import DatabaseService
from ..services.notifier_service import NotifierService
from ..services.orchestrator_service import OrchestratorService
from ..services.security_service import SecurityService
from ..services.validator_service import ValidatorService

# set logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

database_service = DatabaseService()
validator_service = ValidatorService()
notifier_service = NotifierService()
awsapi_service = AwsApiService()
security_service = SecurityService()
ami_details_service = AmiDetailsService()
orchestrator_service = OrchestratorService()
constants_service = ConstantsService()

# static variable delcarations
OPERATOR = "AMI_ERROR_RECEIVER"
TEMPLATE_FILE = "lifecycle_event_notification.template"
ERROR_TEMPLATE_FILE = "lifecycle_event_notification_error.template"

# boto3
stepfunctions_client = boto3.client('stepfunctions')

def lambda_handler(event, context):
    # read the event to json
    logger.debug(json.dumps(event, indent=2))

    try:

        if event and event["Records"]:
            logger.info(f"New event consumed consisting of {len(event['Records'])} record(s).")
            for record in event["Records"]:

                logger.debug(json.loads(record['body']))
                
                json_request = json.loads(record['body'])

                logger.debug(json.dumps(json_request, indent=2))

                # validate the API key
                if 'api_key' not in json_request:
                    raise ValueError(f"An api_key must be included as part of the json payload of the request.")
                
                # if the api_key is not valid an exception will be raised
                security_service.is_ami_error_receiver_authorized(json_request['api_key'])

                if 'lifecycle_id' not in json_request:
                    raise ValueError(f"lifecycle_id must be included as part of the json payload of the request.")
        
                lifecycle_id = json_request['lifecycle_id']

                # validate the structure and basic logic of request 
                # if the request is not valid a ValidationError exception will be raised
                validator_service.validate_lifecycle_definition_error_receiver_request(json_request)

                # write the event result to dynamodb
                lifecycle_definition = database_service.update_event_error(lifecycle_id, json_request)
                
                response = {
                    "lifecycle_id": lifecycle_definition['lifecycle_id'],
                    "action": "Error state notified",
                }

                return {
                    'statusCode': 200,
                    'body': json.dumps(response),
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
            # definition is not defined
            template_attributes['lifecycle_id'] = "UNDEFINED"
            template_attributes['stack_tag'] = "UNDEFINED"
            template_attributes['status_url'] = "UNDEFINED"
        else:
            # definition is defined
            if "lifecycle_id" in lifecycle_definition:
                template_attributes['lifecycle_id'] = lifecycle_definition['lifecycle_id']
                template_attributes['status_url'] = awsapi_service.get_ami_status_endpoint(lifecycle_definition['lifecycle_id'])
            else:
                template_attributes['lifecycle_id'] = "UNDEFINED"
                template_attributes['status_url'] = "UNDEFINED"
            
            if "stack_tag" in lifecycle_definition:
                template_attributes['stack_tag'] = lifecycle_definition['stack_tag']
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
