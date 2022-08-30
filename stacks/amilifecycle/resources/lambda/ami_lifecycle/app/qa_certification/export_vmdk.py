#!/usr/bin/env python

"""
    export_vmdk.py:
    Lambda function that begins a VM Export process in which the AMI is exported to VDMK format
    and persisted to an S3 bucket for the AMI Lifecycle QA_CERTIFICATION State Machine.
"""

import datetime
import json
import logging
import os
import traceback

import boto3

from ..services.constants_service import ConstantsService
from ..services.error_notifier_service import ErrorNotifierService

# constants
OPERATOR = "QA_CERTIFICATION_VMDK_EXPORT"
TEMPLATE_FILE = "state_machine_error.template"

# get env vars
export_bucket = os.environ['EXPORT_BUCKET']
export_role = os.environ['EXPORT_ROLE']

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
        lifecycle_id = event['qa_certification_operation']['input']["lifecycle_id"]
        logger.debug(f"ami_id = {ami_id}")
        logger.debug(f"ami_name = {ami_name}")

        # export the ami image to vmdk
        ec2_client = boto3.client('ec2')
        response = ec2_client.export_image(
            DiskImageFormat='VMDK',
            ImageId=ami_id,
            S3ExportLocation={
                'S3Bucket': export_bucket,
                'S3Prefix': f'exports/{lifecycle_id}/{ami_id}/'
            },
            RoleName=export_role
        )

        logger.info(f"Image {ami_id} is being exported to s3 bucket {export_bucket}/exports/{lifecycle_id}/{ami_id}")
        logger.info(f"Export image task id: {response['ExportImageTaskId']}")

        # set task outputs
        event['qa_certification_operation']['output']['export_image_task_id'] = response['ExportImageTaskId']
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
        
        lifecycle_id = "NOT_DEFINED"
        stack_tag = "NOT_DEFINED"

        if 'qa_certification_operation' in event:
            if 'input' in event['qa_certification_operation']:
                if 'cfn_stack_name' in event['qa_certification_operation']['input']:
                    stack_tag = event['qa_certification_operation']['input']['cfn_stack_name']

        if 'qa_certification_operation' in event:
            if 'input' in event['qa_certification_operation']:
                if 'cfn_stack_name' in event['qa_certification_operation']['input']:
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
