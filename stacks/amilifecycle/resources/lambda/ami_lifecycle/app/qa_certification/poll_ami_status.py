#!/usr/bin/env python

"""
    poll_ami_status.py:
    Lambda function that checks the status of an AMI for the AMI Lifecycle
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
OPERATOR = "QA_CERTIFICATION_POLL_AMI_STATUS"
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
        ami_id = event['qa_certification_operation']['input']["ami_id"]
        ami_owner = event['qa_certification_operation']['input']["ami_owner"]
        ami_name = event['qa_certification_operation']['input']["ami_name"]
        ami_region = event['qa_certification_operation']['input']["ami_region"]

        ami_response = ec2_client.describe_images(
            Filters=[
                {
                    'Name': 'state',
                    'Values': [
                        'available'
                    ]
                },
            ],
            ImageIds=[
                ami_id
            ],
            Owners=[
                ami_owner
            ]
        )

        # get the ami state
        if len(ami_response['Images']) == 0:
            msg = (
                f"Unable to export AMI to VMDK as the provided AMI was not found. " +
                f"Ami Id: {ami_id}, ami_owner: {ami_owner}, ami_region: {ami_region}, " +
                f"ami_name: {ami_name}."
            )
            raise ValueError(msg)


        ami_state = ami_response['Images'][0]['State']

        # aws only allows 1 active vmdk export task at a time
        # make sure there are no active exports before proceeding
        export_response = ec2_client.describe_export_image_tasks(
            Filters=[
                {
                    'Name': 'task-state',
                    'Values': [
                        'active',
                        'deleting'
                    ]
                }
            ]
        )

        logger.debug("export_response")
        logger.debug(export_response)

        active_vmdk_export_tasks = False
        if len(export_response['ExportImageTasks']) > 0:
            active_vmdk_export_tasks = True


        # set task outputs
        event['qa_certification_operation']['output']['ami_state'] = str(ami_state).upper()
        event['qa_certification_operation']['output']['active_vmdk_export_tasks'] = active_vmdk_export_tasks
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
