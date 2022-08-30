#!/usr/bin/env python

"""
    delete_dynamic_imagebuilder.py:
    Lambda function that deletes the dynamically created EC2 Image Builder resources
    that were created during an AMI patch operation as part of the AMI Lifecycle 
    AMI_PATCH State Machine.
"""

import datetime
import json
import logging
import traceback

import boto3

from ..services.constants_service import ConstantsService
from ..services.error_notifier_service import ErrorNotifierService

# constants
OPERATOR = "AMI_PATCH_DELETE_DYNAMIC_IMAGEBUILDER"
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

        # get details from state machine output
        component_build_version_arn = event['patch_ami_operation']['output']['component_build_version_arn']
        image_recipe_arn = event['patch_ami_operation']['output']['image_recipe_arn']
        image_pipeline_arn = event['patch_ami_operation']['output']['image_pipeline_arn']
        infrastructure_configuration_arn = event['patch_ami_operation']['output']['infrastructure_configuration_arn']
        distribution_configuration_arn = event['patch_ami_operation']['output']['distribution_configuration_arn']
        image_build_version_arn = event['patch_ami_operation']['output']["image_build_version_arn"]

        # https://docs.aws.amazon.com/imagebuilder/latest/userguide/delete-resources.html

        # delete the dynamically created imagebuilder pipeline
        response_delete_pipeline = imagebuilder_client.delete_image_pipeline(
            imagePipelineArn=image_pipeline_arn
        )

        # delete the dynamically created imagebuilder recipe
        response_delete_recipe = imagebuilder_client.delete_image_recipe(
            imageRecipeArn=image_recipe_arn
        )

        # delete the dynamically created imagebuilder distribution configuration
        response_delete_infra_cfg = imagebuilder_client.delete_infrastructure_configuration(
            infrastructureConfigurationArn=infrastructure_configuration_arn
        )

        # delete the dynamically created imagebuilder distribution configuration
        response_delete_distrib_cfg = imagebuilder_client.delete_distribution_configuration(
            distributionConfigurationArn=distribution_configuration_arn
        )

        # delete the dynamically created imagebuilder component
        response_delete_component = imagebuilder_client.delete_component(
            componentBuildVersionArn=component_build_version_arn
        )

        # delete the dynamically created image component (NOT the generated AMIs)
        response = imagebuilder_client.delete_image(
            imageBuildVersionArn=image_build_version_arn
        )

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
