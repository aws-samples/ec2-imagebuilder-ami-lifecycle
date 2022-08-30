#!/usr/bin/env python

"""
    entry_point.py:
    Lambda function that notifies the AMI Lifecycle Orchestrator API
    of the success/failure of the AMI Lifecycle AMI_BUILD State Machine.
"""

import datetime
import json
import logging
import traceback

import boto3

from ..services.constants_service import ConstantsService
from ..services.error_notifier_service import ErrorNotifierService
from ..services.security_service import SecurityService

# constants
OPERATOR = "AMI_BUILD_EVENT_NOTIFIER"
TEMPLATE_FILE = "state_machine_error.template"

# boto 3
imagebuilder_client = boto3.client('imagebuilder')

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
        notifier_payload['event_outputs']['name'] = constants_service.EVENT_BUILD_AMI
        notifier_payload['event_outputs']['status'] = constants_service.STATUS_COMPLETED
        notifier_payload['event_outputs']['status_date'] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        notifier_payload['event_outputs']['product_ver'] = event['build_ami_operation']['input']["product_ver"]
        notifier_payload['event_outputs']['product_name'] = event['build_ami_operation']['input']["product_name"]
        notifier_payload['event_outputs']['commit_ref'] = event['build_ami_operation']['input']["commit_ref"]

        event_properties = {
            "task": OPERATOR,
            "ami_details": event['build_ami_operation']['output']['ami_details'],
            "imagebuilder_image_arn": event['build_ami_operation']['output']['image']['arn'],
            "imagebuilder_image_name": event['build_ami_operation']['output']['image']['name'],
            "imagebuilder_image_creation_date" : event['build_ami_operation']['output']['image']['dateCreated'],
            "imagebuilder_imagerecipe_arn": event['build_ami_operation']['output']['image']['imageRecipe']['arn'],
            "imagebuilder_imagerecipe_name": event['build_ami_operation']['output']['image']['imageRecipe']['name'],
            "imagebuilder_recipe_components": event['build_ami_operation']['output']['image']['imageRecipe']['components'],
            "imagebuilder_imagerecipe_creation_date" : event['build_ami_operation']['output']['image']['imageRecipe']['dateCreated'],
            "imagebuilder_source_pipeline_name": event['build_ami_operation']['output']['image']['sourcePipelineArn']
        }

        notifier_payload['event_outputs']['properties'] = event_properties

        # finalize event outputs
        event['build_ami_operation']['output']['event_outputs'] = notifier_payload['event_outputs']
        event['build_ami_operation']['output']['status'] = constants_service.STATUS_COMPLETED
        event['build_ami_operation']['output']['hasError'] = False

        event['event_outputs'] =  notifier_payload['event_outputs']
        event['event_outputs']['lifecycle_id'] = event['build_ami_operation']['input']["lifecycle_id"]
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
