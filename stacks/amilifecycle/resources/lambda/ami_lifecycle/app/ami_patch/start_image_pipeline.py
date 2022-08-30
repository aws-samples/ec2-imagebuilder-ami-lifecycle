#!/usr/bin/env python

"""
    start_image_pipeline.py:
    Lambda function that starts an EC2 Image Builder pipeline in order
    to patch an AMI as part of the AMI Lifecycle AMI_PATCH State Machine.
"""

import datetime
import json
import logging
import random
import string
import traceback

import boto3

from ..services.constants_service import ConstantsService
from ..services.error_notifier_service import ErrorNotifierService

# constants
OPERATOR = "AMI_PATCH_START_IMAGE_PIPELINE"
TEMPLATE_FILE = "state_machine_error.template"

# boto 3
imagebuilder_client = boto3.client('imagebuilder')

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

        # get details from state machine input
        lifecycle_id = event['patch_ami_operation']['input']["lifecycle_id"]
        cfn_stack_name = event['patch_ami_operation']['input']["cfn_stack_name"]
        image_pipeline_arn = event['patch_ami_operation']['output']['image_pipeline_arn']

        # checks have passed, start execution of the imagebuilder pipeline to build the ami
        client_token = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 10))
        execution_response = imagebuilder_client.start_image_pipeline_execution(
            imagePipelineArn=image_pipeline_arn,
            clientToken=client_token
        )

        event['patch_ami_operation']['output']['status'] = constants_service.STATUS_COMPLETED
        event['patch_ami_operation']['output']['hasError'] = False
        event['patch_ami_operation']['output']["image_build_client_token"] = execution_response['clientToken']
        event['patch_ami_operation']['output']["image_build_version_arn"] = execution_response['imageBuildVersionArn']

        return {
            'statusCode': 200,
            'body': event,
            'headers': {'Content-Type': 'application/json'}
        }

    except Exception as e:
        
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        stack_trace = traceback.format_exc()

        logger.error(f'Error in executing {OPERATOR} operation: {str(e)}')

        event['patch_ami_operation']['output']['status'] = constants_service.STATUS_ERROR
        event['patch_ami_operation']['output']['hasError'] = True
        event['patch_ami_operation']['output']['errorMessage'] = str(e)
        
        # create error payload to send to the api
        error_payload = {}
        error_payload['name'] = constants_service.EVENT_BUILD_AMI
        error_payload['status'] = constants_service.STATUS_ERROR
        error_payload['status_date'] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        
        lifecycle_id = "NOT_DEFINED"
        stack_tag = "NOT_DEFINED"

        if 'patch_ami_operation' in event:
            if 'input' in event['patch_ami_operation']:
                if 'cfn_stack_name' in event['patch_ami_operation']['input']:
                    stack_tag = event['patch_ami_operation']['input']['cfn_stack_name']

        if 'patch_ami_operation' in event:
            if 'input' in event['patch_ami_operation']:
                if 'cfn_stack_name' in event['patch_ami_operation']['input']:
                    lifecycle_id = event['patch_ami_operation']['input']['lifecycle_id']

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
