#!/usr/bin/env python

"""
    notify.py:
    Lambda function that notifies the AMI Lifecycle Orchestrator API
    of the success/failure of the AMI Lifecycle SMOKE_TESTS State Machine.
"""

import datetime
import json
import logging
import os
import traceback

import boto3

from ..services.constants_service import ConstantsService
from ..services.error_notifier_service import ErrorNotifierService
from ..services.security_service import SecurityService

# constants
OPERATOR = "SMOKE_TESTS_EVENT_NOTIFIER"
TEMPLATE_FILE = "state_machine_error.template"

# boto 3
imagebuilder_client = boto3.client('imagebuilder')
sqs_client = boto3.client('sqs')

# services
constants_service = ConstantsService()
security_service = SecurityService()
error_notifier_service = ErrorNotifierService()

def lambda_handler(event, context):
    # set logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # env vars
    EVENT_RECEIVER_QUEUE_URL = os.environ['EVENT_RECEIVER_QUEUE_URL']
    PATCH_EVENT_RECEIVER_QUEUE_URL = os.environ['PATCH_EVENT_RECEIVER_QUEUE_URL']

    # print the event details
    logger.debug(json.dumps(event, indent=2))

    try:

        # get the operation_type
        operation_type = event['smoke_test_operation']['output']['operation_type']
        
        if operation_type == constants_service.AMI_CREATION:
            event_name = constants_service.EVENT_SMOKE_TESTS_AMI_CREATE
            
        if operation_type == constants_service.AMI_PATCH:
            event_name = constants_service.EVENT_SMOKE_TESTS_AMI_PATCH

        # build response object to send to the API Orchestrator
        notifier_payload = {}
        notifier_payload['event_outputs'] = {}
        notifier_payload['event_outputs']['name'] = event_name
        notifier_payload['event_outputs']['status'] = constants_service.STATUS_COMPLETED
        notifier_payload['event_outputs']['status_date'] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

        event_properties = {
            "task": OPERATOR,
            "smoke_tests_status": "PASSED"
        }

        notifier_payload['event_outputs']['properties'] = event_properties

        # finalize event outputs
        event['smoke_test_operation']['output']['event_outputs'] = notifier_payload['event_outputs']
        event['smoke_test_operation']['output']['status'] = constants_service.STATUS_COMPLETED
        event['smoke_test_operation']['output']['hasError'] = False

        event['event_outputs'] =  notifier_payload['event_outputs']
        event['event_outputs']['lifecycle_id'] = event['smoke_test_operation']['output']['lifecycle_id']
        event['event_outputs']['operation_type'] = event['smoke_test_operation']['output']['operation_type']
        
        if operation_type == constants_service.AMI_CREATION:
            event['event_outputs']['api_key'] = security_service.get_ami_creation_receiver_api_key()
            
        if operation_type == constants_service.AMI_PATCH:
            event['event_outputs']['api_key'] = security_service.get_ami_patch_receiver_api_key()

        sns_event = {}
        sns_event['task_details'] = {}
        sns_event['task_details']['value'] = event['event_outputs']

    
        if operation_type == constants_service.AMI_CREATION:
            queue_url = EVENT_RECEIVER_QUEUE_URL
        
        if operation_type == constants_service.AMI_PATCH:
            queue_url = PATCH_EVENT_RECEIVER_QUEUE_URL

        sqs_response = sqs_client.send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps(sns_event)
        )

        return {
            'statusCode': 200,
            'body': event,
            'headers': {'Content-Type': 'application/json'}
        }

    except Exception as e:
        
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        stack_trace = traceback.format_exc()

        logger.error(f'Error in executing {OPERATOR} operation: {str(e)}')

        event['smoke_test_operation']['output']['status'] = constants_service.STATUS_ERROR
        event['smoke_test_operation']['output']['hasError'] = True
        event['smoke_test_operation']['output']['errorMessage'] = str(e)
        
        # create error payload to send to the api
        error_payload = {}
        error_payload['name'] = constants_service.EVENT_SMOKE_TESTS
        error_payload['status'] = constants_service.STATUS_ERROR
        error_payload['status_date'] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        
        lifecycle_id = "NOT_DEFINED"
        stack_tag = "NOT_DEFINED"

        if 'lifecycle_id' in event:
            lifecycle_id = event['smoke_test_operation']['output']['lifecycle_id']

        if 'stack_tag' in event:
            stack_tag = event['smoke_test_operation']['output']['stack_tag']

        properties = {
            'task': OPERATOR,
            "error": str(e),
            "stack_trace": stack_trace,
            "stack_tag": stack_tag,
            "lifecycle_id": lifecycle_id
        }

        error_payload['properties'] = properties

        subject = f"ERROR in {OPERATOR} state machine event for {stack_tag}"

        try:
            error_notifier_service.send_notification(
                subject=subject,
                template_name=TEMPLATE_FILE,
                template_attributes=error_payload,
                error_message=str(e),
                stack_trace=stack_trace

            )
        except Exception as err:
            logger.error(f"An error occurred attempting to send error notification: {str(err)}")

        return {
            'statusCode': 500,
            'body': event,
            'headers': {'Content-Type': 'application/json'}
        }
