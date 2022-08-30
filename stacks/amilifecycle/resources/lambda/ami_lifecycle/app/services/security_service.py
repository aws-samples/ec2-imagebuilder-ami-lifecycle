#!/usr/bin/env python

"""
    security_service.py:
    service that interacts with SecretsManager to obtain Orchestrator API keys.
"""

import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class SecurityService:

    # boto 3
    client = boto3.client('secretsmanager')

    __api_key_ami_creation_receiver = os.environ['AMI_CREATION_RECEIVER_SECRET_NAME']
    __api_key_ami_error_receiver = os.environ['AMI_ERROR_RECEIVER_SECRET_NAME']
    __api_key_ami_creation_qa_cerification = os.environ['AMI_CREATION_QA_CERTIFY_SECRET_NAME']
    __api_key_ami_patch_receiver = os.environ['AMI_PATCH_RECEIVER_SECRET_NAME']

    # API Keys
    __API_KEY_SECRET_BASE_PATH="/ami-lifecycle/api-keys"
    __API_KEY_AMI_CREATION_RECEIVER = f"{__API_KEY_SECRET_BASE_PATH}/{__api_key_ami_creation_receiver}"
    __API_KEY_AMI_ERROR_RECEIVER = f"{__API_KEY_SECRET_BASE_PATH}/{__api_key_ami_error_receiver}"
    __API_KEY_AMI_CREATION_QA_CERTIFICATION = f"{__API_KEY_SECRET_BASE_PATH}/{__api_key_ami_creation_qa_cerification}"
    __API_KEY_AMI_PATCH_RECEIVER = f"{__API_KEY_SECRET_BASE_PATH}/{__api_key_ami_patch_receiver}"

    def get_service_name(self) -> str:
        return "security service"


    def get_ami_creation_receiver_api_key(self) -> str:
        response = self.client.get_secret_value(
            SecretId=self.__API_KEY_AMI_CREATION_RECEIVER,
        )
        return response['SecretString']


    def get_ami_error_receiver_api_key(self) -> str:
        response = self.client.get_secret_value(
            SecretId=self.__API_KEY_AMI_ERROR_RECEIVER,
        )
        return response['SecretString']

    
    def get_ami_creation_qa_certification_api_key(self) -> str:
        response = self.client.get_secret_value(
            SecretId=self.__API_KEY_AMI_CREATION_QA_CERTIFICATION,
        )
        return response['SecretString']


    def get_ami_patch_receiver_api_key(self) -> str:
        response = self.client.get_secret_value(
            SecretId=self.__API_KEY_AMI_PATCH_RECEIVER,
        )
        return response['SecretString']
