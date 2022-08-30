#!/usr/bin/env python

"""
    api_key_generator.py: 
    Cloudformation custom resource lambda handler which performs the following tasks:
    * creates API keys for the Orchestrator API endpoints
    * stores the API keys in AWS Secrets Manager
"""

import json
import logging
import random
import string

import boto3
import botocore

# set logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# constants
API_KEY_LENGTH = 30

# boto3
client = boto3.client('secretsmanager')

def generate_api_key() -> str:
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(API_KEY_LENGTH))


def lambda_handler(event, context):

    # print the event details
    logger.debug(json.dumps(event, indent=2))

    props = event['ResourceProperties']
    ami_creation_post_secret_name = props['AMI_CREATION_POST_SECRET_NAME']
    ami_creation_put_secret_name = props['AMI_CREATION_PUT_SECRET_NAME']
    ami_creation_status_secret_name = props['AMI_CREATION_STATUS_SECRET_NAME']
    ami_creation_receiver_secret_name = props['AMI_CREATION_RECEIVER_SECRET_NAME']
    ami_patch_receiver_secret_name = props['AMI_PATCH_RECEIVER_SECRET_NAME']
    ami_error_receiver_secret_name = props['AMI_ERROR_RECEIVER_SECRET_NAME']
    ami_creation_qa_certification_secret_name = props['AMI_CREATION_QA_CERTIFICATION_SECRET_NAME']
    ami_creation_mark_for_production_secret_name = props['AMI_CREATION_MARK_FOR_PRODUCTION_SECRET_NAME']
    ami_creation_timeline_secret_name = props['AMI_CREATION_TIMELINE_SECRET_NAME']
    ami_patch_post_secret_name = props['AMI_PATCH_POST_SECRET_NAME']
    ami_patch_put_secret_name = props['AMI_PATCH_PUT_SECRET_NAME']
    ami_patch_timeline_secret_name = props['AMI_PATCH_TIMELINE_SECRET_NAME']
    ami_patch_mark_for_production_secret_name = props['AMI_PATCH_MARK_FOR_PRODUCTION_SECRET_NAME']

    secrets_manager_path = f"/ami-lifecycle/api-keys"

    # generate the api keys
    ami_creation_post_key = generate_api_key()
    ami_creation_put_key = generate_api_key()
    ami_status_get_key = generate_api_key()
    ami_creation_receiver_key = generate_api_key()
    ami_patch_receiver_key = generate_api_key()
    ami_error_receiver_key = generate_api_key()
    ami_creation_qa_certify_key = generate_api_key()
    ami_creation_mark_for_production_key = generate_api_key()
    ami_creation_timeline_key = generate_api_key()
    ami_patch_post_key = generate_api_key()
    ami_patch_put_key = generate_api_key()
    ami_patch_timeline_key = generate_api_key()
    ami_patch_mark_for_production_key = generate_api_key()

    api_keys = []
    
    ami_creation_post_secret = {
        "Name": f"{secrets_manager_path}/{ami_creation_post_secret_name}",
        "Secret": ami_creation_post_key,
        "Description": "API Key for POST /ami-creation/lifecycles"
    }
    api_keys.append(ami_creation_post_secret)

    ami_creation_put_secret = {
        "Name": f"{secrets_manager_path}/{ami_creation_put_secret_name}",
        "Secret": ami_creation_put_key,
        "Description": "API Key for PUT /ami-creation/lifecycles"
    }
    api_keys.append(ami_creation_put_secret)

    ami_status_secret = {
        "Name": f"{secrets_manager_path}/{ami_creation_status_secret_name}",
        "Secret": ami_status_get_key,
        "Description": "API Key for GET /ami-creation/lifecycles/{lifecycle-id}/status"
    }
    api_keys.append(ami_status_secret)

    ami_creation_qa_certify_secret = {
        "Name": f"{secrets_manager_path}/{ami_creation_qa_certification_secret_name}",
        "Secret": ami_creation_qa_certify_key,
        "Description": "API Key for POST /ami-creation/lifecycles/{lifecycle-id}/certify"
    }
    api_keys.append(ami_creation_qa_certify_secret)

    ami_creation_mark_for_production_secret = {
        "Name": f"{secrets_manager_path}/{ami_creation_mark_for_production_secret_name}",
        "Secret": ami_creation_mark_for_production_key,
        "Description": "API Key for POST /ami-creation/lifecycles/{lifecycle-id}/approve"
    }
    api_keys.append(ami_creation_mark_for_production_secret)

    ami_timeline_secret = {
        "Name": f"{secrets_manager_path}/{ami_creation_timeline_secret_name}",
        "Secret": ami_creation_timeline_key,
        "Description": "API Key for GET /ami-creation/lifecycles/{lifecycle-id}/timeline"
    }
    api_keys.append(ami_timeline_secret)

    ami_creation_receiver_secret = {
        "Name": f"{secrets_manager_path}/{ami_creation_receiver_secret_name}",
        "Secret": ami_creation_receiver_key,
        "Description": "API Creation Event Receiver"
    }
    api_keys.append(ami_creation_receiver_secret)

    ami_patch_receiver_secret = {
        "Name": f"{secrets_manager_path}/{ami_patch_receiver_secret_name}",
        "Secret": ami_patch_receiver_key,
        "Description": "API Patch Event Receiver"
    }
    api_keys.append(ami_patch_receiver_secret)

    ami_error_receiver_secret = {
        "Name": f"{secrets_manager_path}/{ami_error_receiver_secret_name}",
        "Secret": ami_error_receiver_key,
        "Description": "API Error Event Receiver"
    }
    api_keys.append(ami_error_receiver_secret)

    amipatch_timeline_secret = {
        "Name": f"{secrets_manager_path}/{ami_patch_timeline_secret_name}",
        "Secret": ami_creation_timeline_key,
        "Description": "API Key for GET /ami-patch/lifecycles/{lifecycle-id}/timeline"
    }
    api_keys.append(amipatch_timeline_secret)

    ami_patch_post_secret = {
        "Name": f"{secrets_manager_path}/{ami_patch_post_secret_name}",
        "Secret": ami_patch_post_key,
        "Description": "API Key for POST /ami-patch/lifecycles"
    }
    api_keys.append(ami_patch_post_secret)

    ami_patch_put_secret = {
        "Name": f"{secrets_manager_path}/{ami_patch_put_secret_name}",
        "Secret": ami_patch_put_key,
        "Description": "API Key for PUT /ami-patch/lifecycles"
    }
    api_keys.append(ami_patch_put_secret)

    ami_patch_timeline_secret = {
        "Name": f"{secrets_manager_path}/{ami_patch_timeline_secret_name}",
        "Secret": ami_patch_timeline_key,
        "Description": "API Key for GET /ami-patch/lifecycles/{lifecycle-id}/timeline"
    }
    api_keys.append(ami_patch_timeline_secret)

    ami_patch_mark_for_production_secret = {
        "Name": f"{secrets_manager_path}/{ami_patch_mark_for_production_secret_name}",
        "Secret": ami_patch_mark_for_production_key,
        "Description": "API Key for POST /ami-patch/lifecycles/{lifecycle-id}/approve"
    }
    api_keys.append(ami_patch_mark_for_production_secret)

    if event['RequestType'] != 'Delete':

        try:

            for api_key in api_keys:

                try:
                    response = client.create_secret(
                        Name=api_key['Name'],
                        Description=api_key['Description'],
                        SecretString=api_key['Secret']
                    )

                except client.exceptions.ResourceExistsException:
                    response = client.put_secret_value(
                        SecretId=api_key['Name'],
                        SecretString=api_key['Secret']
                    )

                except client.exceptions.InvalidRequestException as err:
                    logger.debug('Ignore operations on pending secret deletions.')

                except botocore.exceptions.ClientError as err:
                    raise err

            
        except Exception as err:
            raise err

        output = {
            'PhysicalResourceId': f"secrets-manager-api-keys",
            'Data': {
                'secrets-manager-api-keys': api_keys
            }
        }
        logger.info("Output: " + json.dumps(output))
        return output

    # handle delete
    else:

        try:

            for api_key in api_keys:

                    try:
                        client.delete_secret(
                            SecretId=api_key['Name'],
                            ForceDeleteWithoutRecovery=True
                        )

                    except client.exceptions.InvalidRequestException as err:
                        logger.debug('Ignore operations on pending secret deletions.')

                    except botocore.exceptions.ClientError as err:
                        raise err

        except botocore.exceptions.ClientError as err:
            raise err

        output = {
            'PhysicalResourceId': f"secrets-manager-api-keys",
            'Data': {
                'secrets-manager-api-keys': api_keys
            }
        }
        logger.info("Output: " + json.dumps(output))
        return output
