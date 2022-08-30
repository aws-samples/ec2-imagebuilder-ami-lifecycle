#!/usr/bin/env python

"""
    notify.py:
    Lambda function that notifies the AMI Lifecycle Orchestrator API
    of the success/failure of the AMI Lifecycle QA_CERTIFICATION State Machine.
"""

import datetime
import json
import logging
import traceback

from ..services.constants_service import ConstantsService
from ..services.error_notifier_service import ErrorNotifierService
from ..services.security_service import SecurityService

# constants
OPERATOR = "QA_CERTIFICATION_EVENT_NOTIFIER"
TEMPLATE_FILE = "state_machine_error.template"

# services
constants_service = ConstantsService()
security_service = SecurityService()
error_notifier_service = ErrorNotifierService()

def lambda_handler(event, context):
    # set logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # print the event details
    logger.debug(json.dumps(event, indent=2))

    try:

        # build response object to send to the API Orchestrator
        notifier_payload = {}
        notifier_payload['event_outputs'] = {}
        notifier_payload['event_outputs']['name'] = constants_service.EVENT_QA_CERTIFICATION_REQUEST
        notifier_payload['event_outputs']['status'] = constants_service.STATUS_COMPLETED
        notifier_payload['event_outputs']['status_date'] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

        # get details from previous stage
        ami_id = event['qa_certification_operation']['input']["ami_id"]
        ami_owner = event['qa_certification_operation']['input']["ami_owner"]
        ami_name = event['qa_certification_operation']['input']["ami_name"]
        ami_region = event['qa_certification_operation']['input']["ami_region"]

        export_image_id = event['qa_certification_operation']['output']['export_image_id']
        export_bucket = event['qa_certification_operation']['output']['export_bucket']
        export_bucket_prefix = event['qa_certification_operation']['output']['export_bucket_prefix']
        export_image_path = event['qa_certification_operation']['output']['export_image_path']
        export_presign_s3_url = event['qa_certification_operation']['output']['export_presign_s3_url'] 
        export_image_task_id = event['qa_certification_operation']['output']['export_image_task_id']

        event_properties = {
            "task": OPERATOR,
            "ami_id": ami_id,
            "ami_owner": ami_owner,
            "ami_name": ami_name,
            "ami_region": ami_region,
            "export_image_id": export_image_id,
            "export_bucket": export_bucket,
            "export_bucket_prefix": export_bucket_prefix,
            "export_image_path": export_image_path,
            "export_presign_s3_url": export_presign_s3_url,
            "export_image_task_id": export_image_task_id
        }

        notifier_payload['event_outputs']['properties'] = event_properties

        # finalize event outputs
        event['qa_certification_operation']['output']['event_outputs'] = notifier_payload['event_outputs']
        event['qa_certification_operation']['output']['status'] = constants_service.STATUS_COMPLETED
        event['qa_certification_operation']['output']['hasError'] = False

        event['event_outputs'] =  notifier_payload['event_outputs']
        event['event_outputs']['lifecycle_id'] = event['qa_certification_operation']['input']["lifecycle_id"]
        event['event_outputs']['api_key'] = security_service.get_ami_creation_receiver_api_key()

        return {
            'statusCode': 200,
            'body': event,
            'headers': {'Content-Type': 'application/json'}
        }

    except Exception as e:
        
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        stack_trace = traceback.format_exc()

        logger.error(f'Error in executing {OPERATOR} operation: {str(e)}')

        event['qa_certification_operation']['output']['status'] = constants_service.STATUS_ERROR
        event['qa_certification_operation']['output']['hasError'] = True
        event['qa_certification_operation']['output']['errorMessage'] = str(e)
        
        # create error payload to send to the api
        error_payload = {}
        error_payload['name'] = constants_service.EVENT_QA_CERTIFICATION_REQUEST
        error_payload['status'] = constants_service.STATUS_ERROR
        error_payload['status_date'] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        
        stack_tag = event['qa_certification_operation']['input']['cfn_stack_name']
        lifecycle_id = event['qa_certification_operation']['input']['lifecycle_id']

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
