#!/usr/bin/env python

"""
    create_image_pipeline.py:
    Lambda function that creates an EC2 Image Builder Image Pipeline
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
OPERATOR = "AMI_PATCH_CREATE_IMAGEBUILDER_PIPELINE"
TEMPLATE_FILE = "state_machine_error.template"

# boto 3
imagebuilder_client = boto3.client('imagebuilder')

# services
error_notifier_service = ErrorNotifierService()
constants_service = ConstantsService()

# env vars
AWS_REGION = os.environ['AWS_REGION']
PUBLISHING_ACCOUNT_IDS = os.environ['PUBLISHING_ACCOUNT_IDS'].split(',')
SHARING_ACCOUNT_IDS = os.environ['SHARING_ACCOUNT_IDS'].split(',')
INSTANCE_TYPES = os.environ['INSTANCE_TYPES'].split(',')
INSTANCE_PROFILE = os.environ['INSTANCE_PROFILE']
SECURITY_GROUP_ID = os.environ['SECURITY_GROUP_ID']
SUBNET_ID = os.environ['SUBNET_ID']
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
RESOURCE_TAGS = json.loads(os.environ['RESOURCE_TAGS'])


def create_distribution_configuration(        
        name: str, 
        description: str,
        tags: dict,
    ) -> str:
    response = imagebuilder_client.create_distribution_configuration(
        name=name,
        description=description,
        distributions=[
            {
                'region': AWS_REGION,
                'amiDistributionConfiguration': {
                    'name': "AmiLifecycle-{{ imagebuilder:buildDate }}",
                    'description': description,
                    'targetAccountIds': PUBLISHING_ACCOUNT_IDS,
                    'amiTags': {
                        'PublishTargets': ",".join(PUBLISHING_ACCOUNT_IDS),
                        'SharingTargets': ",".join(SHARING_ACCOUNT_IDS)
                    },
                    'launchPermission': {
                        'userIds': SHARING_ACCOUNT_IDS
                    }
                }
            }
        ],
        tags=tags,
        clientToken=''.join(random.choices(string.ascii_uppercase + string.digits, k = 10))
    )

    return response['distributionConfigurationArn']


def create_infrastructure_configuration(
        name: str, 
        description: str,
        tags: dict
    ) -> str:
    response = imagebuilder_client.create_infrastructure_configuration(
        name=name,
        description=description,
        instanceTypes=INSTANCE_TYPES,
        instanceProfileName=INSTANCE_PROFILE,
        securityGroupIds=[
            SECURITY_GROUP_ID,
        ],
        subnetId=SUBNET_ID,
        terminateInstanceOnFailure=True,
        snsTopicArn=SNS_TOPIC_ARN,
        resourceTags=RESOURCE_TAGS,
        tags=tags,
        clientToken=''.join(random.choices(string.ascii_uppercase + string.digits, k = 10))
    )

    return response['infrastructureConfigurationArn']


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
        image_recipe_arn = event['patch_ami_operation']['output']['image_recipe_arn']

        # declare variables needed to create the pipeline
        pipeline_description = (
            f"AMI Lifecycle patching: {lifecycle_id} / {semantic_version_dot}"[:254]
        )

        client_token=''.join(random.choices(string.ascii_uppercase + string.digits, k = 10))

        name = f'AMI-PATCH-LC-{lifecycle_id}-{semantic_version_dash}-{client_token}'[:98]

        tags = {
            'Event': 'AMI_LIFECYCLE_PATCH',
            'LifecycleId': lifecycle_id,
            'StackTag': cfn_stack_name,
            'SemanticVersion': semantic_version_dot
        }

        infrastructure_configuration_arn = create_infrastructure_configuration(
            name=name,
            description=pipeline_description,
            tags=tags
        )

        distribution_configuration_arn = create_distribution_configuration(
            name=name,
            description=pipeline_description,
            tags=tags
        )

        response = imagebuilder_client.create_image_pipeline(
            name=name,
            description=pipeline_description,
            imageRecipeArn=image_recipe_arn,
            infrastructureConfigurationArn=infrastructure_configuration_arn,
            distributionConfigurationArn=distribution_configuration_arn,
            imageTestsConfiguration={
                'imageTestsEnabled': True,
                'timeoutMinutes': 90
            },
            enhancedImageMetadataEnabled=True,
            status='ENABLED',
            tags=tags,
            clientToken=client_token
        )

    
        # set task outputs
        event['patch_ami_operation']['output']['image_pipeline_arn'] = response['imagePipelineArn']
        event['patch_ami_operation']['output']['image_pipeline_name'] = name
        event['patch_ami_operation']['output']['image_pipeline_request_id'] = response['requestId']
        event['patch_ami_operation']['output']['image_pipeline_client_id'] = response['clientToken']
        event['patch_ami_operation']['output']['infrastructure_configuration_arn'] = infrastructure_configuration_arn
        event['patch_ami_operation']['output']['distribution_configuration_arn'] = distribution_configuration_arn
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
