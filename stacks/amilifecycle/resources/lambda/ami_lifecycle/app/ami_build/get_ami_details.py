#!/usr/bin/env python

"""
    get_ami_details.py:
    Lambda function that gets the details of an AVAILABLE AMI for the 
    AMI Lifecycle AMI_BUILD State Machine.
"""

import datetime
import json
import logging
import traceback

import boto3

from ..services.constants_service import ConstantsService
from ..services.error_notifier_service import ErrorNotifierService

# constants
OPERATOR = "AMI_BUILD_GET_AMI_DETAILS"
TEMPLATE_FILE = "state_machine_error.template"

# boto 3
imagebuilder_client = boto3.client('imagebuilder')
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
        image_build_version_arn = event['build_ami_operation']['output']["image_build_version_arn"]

        response = imagebuilder_client.get_image(
            imageBuildVersionArn=image_build_version_arn
        )

        logger.debug("Imagebuilder get_image:")
        logger.debug(json.dumps(response, indent=2))

        # get the ami state
        ami_state = response['image']['state']['status']

        # add stage specific details
        event['build_ami_operation']['output']['ami_state'] = str(ami_state).upper()
        event['build_ami_operation']['output']['image'] = response['image']
        event['build_ami_operation']['output']['ami_details'] = response['image']['outputResources']['amis']

        # remove some keys we do not need
        del event['build_ami_operation']['output']['image']['infrastructureConfiguration']
        del event['build_ami_operation']['output']['image']['distributionConfiguration']
        del event['build_ami_operation']['output']['image']['imageTestsConfiguration']
        del event['build_ami_operation']['output']['image']['imageRecipe']['blockDeviceMappings']

        event['build_ami_operation']['output']['status'] = constants_service.STATUS_COMPLETED
        event['build_ami_operation']['output']['hasError'] = False

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
        
        stack_tag = event['build_ami_operation']['input']['cfn_stack_name']
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
