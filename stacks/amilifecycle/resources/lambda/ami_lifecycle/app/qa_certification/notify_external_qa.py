#!/usr/bin/env python

"""
    notify_external_qa.py:
    Lambda function that notifies an external QA team about the details of the 
    VM Export vmdk image file as part of the AMI Lifecycle QA_CERTIFICATION State Machine.
"""

import datetime
import json
import logging
import traceback

from ..services.constants_service import ConstantsService
from ..services.error_notifier_service import ErrorNotifierService
from ..services.qa_notifier_service import QANotifierService
from ..services.security_service import SecurityService

# constants
OPERATOR = "QA_CERTIFICATION_NOTIFY_QA"
TEMPLATE_FILE = "state_machine_error.template"
QA_TEMPLATE_FILE="external_qa.template"

# services
error_notifier_service = ErrorNotifierService()
qa_notifier_service = QANotifierService()
constants_service = ConstantsService()
security_service = SecurityService()


def lambda_handler(event, context):
    # set logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # print the event details
    logger.debug(json.dumps(event, indent=2))

    try:

        # get details from previous stage
        lifecycle_id = event['qa_certification_operation']['input']["lifecycle_id"]
        stack_tag = event['qa_certification_operation']['input']["cfn_stack_name"]
        api_url = event['qa_certification_operation']['input']["api_url"]

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
        export_link_expiry = event['qa_certification_operation']['output']['export_link_expiry']
        export_link_expiry_in_days =  int(export_link_expiry / 60 / 60 / 24)

        qa_certify_url = (
            api_url +
            f"/ami-creation/lifecycles/{lifecycle_id}/certify"
        )

        template_attributes = {}
        template_attributes['properties'] = {
            "ami_id": ami_id,
            "ami_name": ami_name,
            "ami_region": ami_region,
            "ami_owner": ami_owner,
            "export_image_id": export_image_id,
            "export_bucket": export_bucket,
            "export_bucket_prefix": export_bucket_prefix,
            "export_image_task_id": export_image_task_id,
            "export_presign_s3_url": export_presign_s3_url,
            "export_image_path": export_image_path,
            "export_link_expiry": export_link_expiry_in_days,
            "lifecycle_id": lifecycle_id,
            "stack_tag": stack_tag,
            "qa_certify_url": qa_certify_url,
            "qa_certify_api_key": security_service.get_ami_creation_qa_certification_api_key()
        }

        qa_notifier_service.send_email_notification(
            subject=f"QA Certifiction request for AMI {ami_id}",
            template_name=QA_TEMPLATE_FILE,
            template_attributes=template_attributes
        )

        # set task outputs
        event['qa_certification_operation']['output']['status'] = constants_service.STATUS_COMPLETED
        event['qa_certification_operation']['output']['hasError'] = False

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
