#!/usr/bin/env python

"""
    create_image_recipe.py:
    Lambda function that creates an EC2 Image Builder Image Recipe
    that will be used to patch an AMI as part of the AMI Lifecycle 
    AMI_PATCH State Machine.
"""

import datetime
import json
import logging
import os
import random
import string
import traceback

import boto3

from ..services.constants_service import ConstantsService
from ..services.error_notifier_service import ErrorNotifierService

# constants
OPERATOR = "AMI_PATCH_CREATE_IMAGEBUILDER_RECIPE"
TEMPLATE_FILE = "state_machine_error.template"

# boto 3
imagebuilder_client = boto3.client('imagebuilder')

# services
error_notifier_service = ErrorNotifierService()
constants_service = ConstantsService()

# env vars
AWS_REGION = os.environ['AWS_REGION']
EBS_VOLUME_SIZE = int(os.environ['EBS_VOLUME_SIZE'])

def lambda_handler(event, context):
    # set logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # print the event details
    logger.debug(json.dumps(event, indent=2))

    try:

        # get details from previous stage
        patch_component_url = event['patch_ami_operation']['input']["patch_component_url"]
        component_build_version_arn = event['patch_ami_operation']['output']['component_build_version_arn']
        lifecycle_id = event['patch_ami_operation']['input']["lifecycle_id"]
        cfn_stack_name = event['patch_ami_operation']['input']["cfn_stack_name"]
        ami_id = event['patch_ami_operation']['input']["ami_id"]
        ami_name = event['patch_ami_operation']['input']["ami_name"]
        ami_region = event['patch_ami_operation']['input']["ami_region"]
        ami_owner = event['patch_ami_operation']['input']["ami_owner"]
        semantic_version_dot = event['patch_ami_operation']['input']["semantic_version_dot"]
        semantic_version_dash = event['patch_ami_operation']['input']["semantic_version_dash"]

        recipe_description = (
            f"AMI Lifecycle patching: {lifecycle_id} / {semantic_version_dot}"[:254]
        )

        client_token = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 10))

        response = imagebuilder_client.create_image_recipe(
            name=f'AMI-PATCH-LC-{lifecycle_id}-{semantic_version_dash}-{client_token}'[:98],
            description=recipe_description,
            semanticVersion=semantic_version_dot,
            components=[
                {
                    'componentArn': component_build_version_arn,
                }
            ],
            parentImage=ami_id,
            blockDeviceMappings=[
                {
                    'deviceName': "/dev/xvda",
                    'ebs': {
                        'encrypted': False,
                        'deleteOnTermination': True,
                        'volumeSize': EBS_VOLUME_SIZE,
                        'volumeType': 'gp2',
                    }
                },
            ],
            tags={
                'Event': 'AMI_LIFECYCLE_PATCH',
                'LifecycleId': lifecycle_id,
                'StackTag': cfn_stack_name,
                'SemanticVersion': semantic_version_dot
            },
            workingDirectory="/imagebuilder",
            clientToken=client_token
        )

    
        # set task outputs
        event['patch_ami_operation']['output']['image_recipe_arn'] = response['imageRecipeArn']
        event['patch_ami_operation']['output']['image_recipe_request_id'] = response['requestId']
        event['patch_ami_operation']['output']['image_recipe_client_id'] = response['clientToken']
        event['patch_ami_operation']['output']['status'] = constants_service.STATUS_COMPLETED
        event['patch_ami_operation']['output']['hasError'] = False

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
        
        stack_tag = event['patch_ami_operation']['input']['cfn_stack_name']
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
