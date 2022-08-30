#!/usr/bin/env python

"""
    generate_download_url.py:
    Lambda function that generates a pre-signed S3 url that allows for on-premises download
    of the exported VDMK file for the AMI Lifecycle QA_CERTIFICATION State Machine.
"""

import datetime
import json
import logging
import os
import traceback

import boto3
from botocore.client import Config

from ..services.constants_service import ConstantsService
from ..services.error_notifier_service import ErrorNotifierService

# constants
OPERATOR = "QA_CERTIFICATION_GENERATE_DOWNLOAD_URL"
TEMPLATE_FILE = "state_machine_error.template"

# get env vars
EXPORT_LINK_EXPIRY = int(os.environ['EXPORT_LINK_EXPIRY'])

# boto 3
s3_client = boto3.client(
    's3',
    config=Config(signature_version='s3v4')
)
ec2_client = boto3.client('ec2')

# services
error_notifier_service = ErrorNotifierService()
constants_service = ConstantsService()


def presign_url(bucket_name, object_name, expiration) -> str:
    return s3_client.generate_presigned_url(
        'get_object',
        Params={
            'Bucket': bucket_name,
            'Key': object_name
        },
        ExpiresIn=expiration
    )


def lambda_handler(event, context):
    # set logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # print the event details
    logger.debug(json.dumps(event, indent=2))

    try:

        # get details from previous stage
        export_image_task_id = event['qa_certification_operation']['output']['export_image_task_id']

        # get the ami export task
        response = ec2_client.describe_export_image_tasks(
            ExportImageTaskIds=[
                export_image_task_id
            ]
        )

        ami_export_task = None


        if len(response['ExportImageTasks']) == 0:
            msg = (
                f"Unable to export AMI to VMDK as the provided Export Task was not found. " +
                f"export_image_task_id: {export_image_task_id}."
            )
            raise ValueError(msg)

        for export_task in response['ExportImageTasks']:
            if export_task['ExportImageTaskId'] == export_image_task_id:
                logger.info(f"Got task id match: {export_task['ExportImageTaskId']}")
                ami_export_task = export_task
                break

        export_image_id=f"{ami_export_task['ExportImageTaskId']}.vmdk"
        export_bucket=f"{ami_export_task['S3ExportLocation']['S3Bucket']}"
        export_bucket_prefix=f"{ami_export_task['S3ExportLocation']['S3Prefix']}"
        export_image_path=f"s3://{export_bucket}/{export_bucket_prefix}{export_image_id}"

        logger.debug(f"image_id = {export_image_id}")
        logger.debug(f"export_bucket = {export_bucket}")
        logger.debug(f"export_bucket_prefix = {export_bucket_prefix}")
        logger.debug(f"image_path = {export_image_path}")

        presign_s3_url = presign_url(
            bucket_name=export_bucket, 
            object_name=f"{export_bucket_prefix}{export_image_id}", 
            expiration=EXPORT_LINK_EXPIRY
        )

        # set task outputs
        event['qa_certification_operation']['output']['export_image_id'] = export_image_id
        event['qa_certification_operation']['output']['export_bucket'] = export_bucket
        event['qa_certification_operation']['output']['export_bucket_prefix'] = export_bucket_prefix
        event['qa_certification_operation']['output']['export_image_path'] = export_image_path
        event['qa_certification_operation']['output']['export_presign_s3_url'] = presign_s3_url
        event['qa_certification_operation']['output']['export_link_expiry'] = EXPORT_LINK_EXPIRY
        
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
