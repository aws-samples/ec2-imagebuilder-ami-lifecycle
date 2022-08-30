#!/usr/bin/env python

"""
    notify.py:
    Lambda function that notifies the AMI Lifecycle Orchestrator API
    of the success/failure of the AMI Lifecycle MARK_FOR_PRODUCTION State Machine.
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
OPERATOR = "MARK_FOR_PRODUCTION_EVENT_NOTIFIER"
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
        operation_type = event['mark_for_production_operation']['input']["operation_type"]

        if operation_type == constants_service.AMI_CREATION:
            event_name = constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE
            
        if operation_type == constants_service.AMI_PATCH:
            event_name = constants_service.EVENT_MARK_FOR_PRODUCTION_PATCH

        # create vulnerability scan properties
        mark_for_production_properties = {}
        mark_for_production_properties['s3_bucket'] = event['mark_for_production_operation']['output']['s3_bucket']
        mark_for_production_properties['s3_object_key'] = event['mark_for_production_operation']['output']['s3_object_key']
        mark_for_production_properties['ami_backup_state'] = event['mark_for_production_operation']['output']['ami_backup_state']

        # build response object to send to the API Orchestrator
        notifier_payload = {}
        notifier_payload['event_outputs'] = {}
        notifier_payload['event_outputs']['name'] = event_name
        notifier_payload['event_outputs']['status'] = constants_service.STATUS_COMPLETED
        notifier_payload['event_outputs']['status_date'] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        notifier_payload['event_outputs']['properties'] = mark_for_production_properties
        notifier_payload['event_outputs']['properties']['task'] = OPERATOR
        notifier_payload['event_outputs']['properties']['approval_status'] = "APPROVED"

        # finalize event outputs
        event['mark_for_production_operation']['output']['event_outputs'] = notifier_payload['event_outputs']
        event['mark_for_production_operation']['output']['status'] = constants_service.STATUS_COMPLETED
        event['mark_for_production_operation']['output']['hasError'] = False

        event['event_outputs'] =  notifier_payload['event_outputs']
        event['event_outputs']['lifecycle_id'] = event['mark_for_production_operation']['input']["lifecycle_id"]
        event['event_outputs']['operation_type'] = event['mark_for_production_operation']['input']["operation_type"]
        
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

        event['mark_for_production_operation']['output']['status'] = constants_service.STATUS_COMPLETED
        event['mark_for_production_operation']['output']['hasError'] = False

        return {
            'statusCode': 200,
            'body': event,
            'headers': {'Content-Type': 'application/json'}
        }

    except Exception as e:
        
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        stack_trace = traceback.format_exc()

        logger.error(f'Error in executing {OPERATOR} operation: {str(e)}')

        event['mark_for_production_operation']['output']['status'] = constants_service.STATUS_ERROR
        event['mark_for_production_operation']['output']['hasError'] = True
        event['mark_for_production_operation']['output']['errorMessage'] = str(e)
        
        # create error payload to send to the api
        error_payload = {}
        error_payload['name'] = operation_type
        error_payload['status'] = constants_service.STATUS_ERROR
        error_payload['status_date'] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

        lifecycle_id = event['mark_for_production_operation']['input']["lifecycle_id"]
        stack_tag = event['mark_for_production_operation']['input']["cfn_stack_name"]

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
