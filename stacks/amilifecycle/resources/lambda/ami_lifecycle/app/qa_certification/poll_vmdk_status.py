#!/usr/bin/env python

"""
    poll_vmdk_status.py:
    Lambda function that polls the status of the VM Export process for the AMI Lifecycle
    QA_CERTIFICATION State Machine.
"""

import datetime
import json
import logging
import traceback

import boto3

from ..services.constants_service import ConstantsService
from ..services.error_notifier_service import ErrorNotifierService

# constants
OPERATOR = "QA_CERTIFICATION_POLL_VMDK_STATUS"
TEMPLATE_FILE = "state_machine_error.template"

# boto 3
ec2_client = boto3.client('ec2')

# services
error_notifier_service = ErrorNotifierService()
constants_service = ConstantsService()

def lambda_handler(event, context):
    # set logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # print the event details
    logger.debug(json.dumps(event, indent=2))

    try:

        # get details from previous stage
        export_image_task_id = event['qa_certification_operation']['output']['export_image_task_id']

        logger.debug(f"export_image_task_id = {export_image_task_id}")

        # check if the ami export is in the completed state
        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_export_image_tasks(
            ExportImageTaskIds=[
                export_image_task_id
            ]
        )

        logger.info(f"Checking if AMI export is in completed state")
        
        # return a NOT_COMPLETED state if the ami export is not completed
        vdmk_export_status = "NOT_COMPLETED"

        if len(response['ExportImageTasks']) == 0:
            msg = (
                f"Unable to export AMI to VMDK as the provided Export Task was not found. " +
                f"export_image_task_id: {export_image_task_id}."
            )
            raise ValueError(msg)

        for export_task in response['ExportImageTasks']:
            if export_task['ExportImageTaskId'] == export_image_task_id:
                logger.info(f"Got task id match: {export_task['ExportImageTaskId']}")
                vdmk_export_status = str(export_task['Status']).upper()
                logger.info(f"Current AMI export state: {vdmk_export_status}")
                break

        logger.info(f"Returning vdmk_export_status: {vdmk_export_status}")

        # set task outputs
        event['qa_certification_operation']['output']['export_image_task_id'] = export_image_task_id
        event['qa_certification_operation']['output']['export_image_task_status'] = vdmk_export_status
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
