#!/usr/bin/env python

"""
    entry_point.py:
    Lambda function that acts as the entry point handler for the AMI Lifecycle
    AMI_BUILD State Machine.
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
OPERATOR = "AMI_BUILD_ENTRY_POINT"
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

    # create objects for tracking task progress
    event['build_ami_operation'] = {}
    event['build_ami_operation']['input'] = {}
    event['build_ami_operation']['output'] = {}

    try:

        # validate inputs
        expected_inputs = [ 
            "lifecycle_id", 
            "cfn_stack_name", 
            "imagebuilder_pipeline_arn",
            "product_ver",
            "product_name",
            "commit_ref"
        ]
        for expected_input in expected_inputs:
            if expected_input not in event or event[expected_input] == "":
                raise ValueError(f"A valid {expected_input} must be provided as part of the {OPERATOR} state machine input")

        # get details from state machine input
        event['build_ami_operation']['input']["lifecycle_id"] = event["lifecycle_id"]
        event['build_ami_operation']['input']["cfn_stack_name"] = event["cfn_stack_name"]
        event['build_ami_operation']['input']["imagebuilder_pipeline_arn"] = event["imagebuilder_pipeline_arn"]
        event['build_ami_operation']['input']["product_ver"] = event["product_ver"]
        event['build_ami_operation']['input']["product_name"] = event["product_name"]
        event['build_ami_operation']['input']["commit_ref"] = event["commit_ref"]

        cfn_stack_name = event["cfn_stack_name"]
        pipeline_arn = event["imagebuilder_pipeline_arn"]

        if pipeline_arn is None:
            raise ValueError(f"imagebuilder_pipeline_arn is not present in the state machine input event.")

        # checks have passed, start execution of the imagebuilder pipeline to build the ami
        client_token = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 10))
        execution_response = imagebuilder_client.start_image_pipeline_execution(
            imagePipelineArn=pipeline_arn,
            clientToken=client_token
        )

        event['build_ami_operation']['output']['status'] = constants_service.STATUS_COMPLETED
        event['build_ami_operation']['output']['hasError'] = False
        event['build_ami_operation']['output']["imagebuilder_pipeline_arn"] = pipeline_arn
        event['build_ami_operation']['output']["execution_client_token"] = execution_response['clientToken']
        event['build_ami_operation']['output']["image_build_version_arn"] = execution_response['imageBuildVersionArn']

        return {
            'statusCode': 200,
            'body': event,
            'headers': {'Content-Type': 'application/json'}
        }

    except Exception as e:
        
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        stack_trace = traceback.format_exc()

        logger.error(f'Error in executing {OPERATOR} operation: {str(e)}')

        event['build_ami_operation']['output']['status'] = constants_service.STATUS_ERROR
        event['build_ami_operation']['output']['hasError'] = True
        event['build_ami_operation']['output']['errorMessage'] = str(e)
        
        # create error payload to send to the api
        error_payload = {}
        error_payload['name'] = constants_service.EVENT_BUILD_AMI
        error_payload['status'] = constants_service.STATUS_ERROR
        error_payload['status_date'] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        
        lifecycle_id = "NOT_DEFINED"
        stack_tag = "NOT_DEFINED"

        if 'build_ami_operation' in event:
            if 'input' in event['build_ami_operation']:
                if 'cfn_stack_name' in event['build_ami_operation']['input']:
                    stack_tag = event['build_ami_operation']['input']['cfn_stack_name']

        if 'build_ami_operation' in event:
            if 'input' in event['build_ami_operation']:
                if 'cfn_stack_name' in event['build_ami_operation']['input']:
                    lifecycle_id = event['build_ami_operation']['input']['lifecycle_id']

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
