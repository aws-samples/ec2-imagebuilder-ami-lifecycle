#!/usr/bin/env python

"""
    ami_backup.py:
    Lambda function that initiates an AMI backup operation in which an AMI is
    saved to an S3 bucket for the AMI Lifecycle MARK_FOR_PRODUCTION State Machine.
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
OPERATOR = "MARK_FOR_PRODUCTION_AMI_BACKUP"
TEMPLATE_FILE = "state_machine_error.template"

# services
error_notifier_service = ErrorNotifierService()
constants_service = ConstantsService()
security_service = SecurityService()

# boto 3
EC2_CLIENT = boto3.client('ec2')

# environment variables
BACKUP_BUCKET = os.environ.get('BUCKET')

def lambda_handler(event, context):
    # set logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # print the event details
    logger.debug(json.dumps(event, indent=2))

    try:

        # get details from previous stage
        ami_id = event['mark_for_production_operation']['input']["ami_id"]

        response = EC2_CLIENT.create_store_image_task(
            ImageId=ami_id,
            Bucket=BACKUP_BUCKET,
            S3ObjectTags=[
                {
                    'Key': 'CommitRef',
                    'Value': event['mark_for_production_operation']['input']["commit_ref"] 
                },
                {
                    'Key': 'ProductVer',
                    'Value': event['mark_for_production_operation']['input']["product_ver"] 
                },
                {
                    'Key': 'ProductName',
                    'Value': event['mark_for_production_operation']['input']["product_name"] 
                },
            ],
            DryRun=False
        )

        event['mark_for_production_operation']['output']['backup_object_key'] = response['ObjectKey']
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
        error_payload['name'] = constants_service.EVENT_BUILD_AMI
        error_payload['status'] = constants_service.STATUS_ERROR
        error_payload['status_date'] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        
        stack_tag = event['mark_for_production_operation']['input']['cfn_stack_name']
        lifecycle_id = event['mark_for_production_operation']['input']['lifecycle_id']

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
