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
    """
        Service that interacts with SecretsManager to obtain Orchestrator API keys.
    """

    # boto 3
    client = boto3.client('secretsmanager')

    # API Keys
    _API_KEY_SECRET_BASE_PATH="/ami-lifecycle/api-keys"
    _API_KEY_AMI_CREATION_POST = f"{_API_KEY_SECRET_BASE_PATH}/{os.environ['AMI_CREATION_POST_SECRET_NAME']}"
    _API_KEY_AMI_CREATION_PUT = f"{_API_KEY_SECRET_BASE_PATH}/{os.environ['AMI_CREATION_PUT_SECRET_NAME']}"
    _API_KEY_AMI_CREATION_STATUS = f"{_API_KEY_SECRET_BASE_PATH}/{os.environ['AMI_CREATION_STATUS_SECRET_NAME']}"
    _API_KEY_AMI_CREATION_TIMELINE = f"{_API_KEY_SECRET_BASE_PATH}/{os.environ['AMI_CREATION_TIMELINE_SECRET_NAME']}"
    _API_KEY_AMI_CREATION_QA_CERTIFY = f"{_API_KEY_SECRET_BASE_PATH}/{os.environ['AMI_CREATION_QA_CERTIFY_SECRET_NAME']}"
    _API_KEY_AMI_CREATION_MARK_FOR_PROD = f"{_API_KEY_SECRET_BASE_PATH}/{os.environ['AMI_CREATION_MARK_FOR_PRODUCTION_SECRET_NAME']}"
    _API_KEY_AMI_PATCH_MARK_FOR_PROD = f"{_API_KEY_SECRET_BASE_PATH}/{os.environ['AMI_PATCH_MARK_FOR_PRODUCTION_SECRET_NAME']}"
    _API_KEY_AMI_CREATION_RECEIVER = f"{_API_KEY_SECRET_BASE_PATH}/{os.environ['AMI_CREATION_RECEIVER_SECRET_NAME']}"
    _API_KEY_AMI_PATCH_RECEIVER = f"{_API_KEY_SECRET_BASE_PATH}/{os.environ['AMI_PATCH_RECEIVER_SECRET_NAME']}"
    _API_KEY_AMI_ERROR_RECEIVER = f"{_API_KEY_SECRET_BASE_PATH}/{os.environ['AMI_ERROR_RECEIVER_SECRET_NAME']}"
    _API_KEY_AMI_PATCH_POST = f"{_API_KEY_SECRET_BASE_PATH}/{os.environ['AMI_PATCH_POST_SECRET_NAME']}"
    _API_KEY_AMI_PATCH_PUT = f"{_API_KEY_SECRET_BASE_PATH}/{os.environ['AMI_PATCH_PUT_SECRET_NAME']}"
    _API_KEY_AMI_PATCH_TIMELINE = f"{_API_KEY_SECRET_BASE_PATH}/{os.environ['AMI_PATCH_TIMELINE_SECRET_NAME']}"


    def get_service_name(self) -> str:
        return "security service"

    def _get_secretsmanager_value(self, secret_id) -> str:
        response = self.client.get_secret_value(
            SecretId=secret_id,
        )
        return response['SecretString']


    def get_status_api_key(self) -> str:
        return self._get_secretsmanager_value(self._API_KEY_AMI_CREATION_STATUS)

    def get_create_receiver_api_key(self) -> str:
        return self._get_secretsmanager_value(self._API_KEY_AMI_CREATION_RECEIVER)

    def get_patch_receiver_api_key(self) -> str:
        return self._get_secretsmanager_value(self._API_KEY_AMI_PATCH_RECEIVER)

    def get_create_timeline_api_key(self) -> str:
        return self._get_secretsmanager_value(self._API_KEY_AMI_CREATION_TIMELINE)

    def get_patch_timeline_api_key(self) -> str:
        return self._get_secretsmanager_value(self._API_KEY_AMI_PATCH_TIMELINE)

    def is_ami_creation_post_authorized(self, api_key: str) -> bool:
        if api_key != self._get_secretsmanager_value(self._API_KEY_AMI_CREATION_POST):
            raise ValueError("Invalid API Key for AMI Lifecycle Create POST operation.")

        return True

    def is_ami_creation_put_authorized(self, api_key: str) -> bool:
        if api_key != self._get_secretsmanager_value(self._API_KEY_AMI_CREATION_PUT):
            raise ValueError("Invalid API Key for AMI Lifecycle Create PUT operation.")

        return True

    def is_ami_creation_status_authorized(self, api_key: str) -> bool:
        if api_key != self._get_secretsmanager_value(self._API_KEY_AMI_CREATION_STATUS):
            raise ValueError("Invalid API Key for AMI Get Status operation.")

        return True

    def is_ami_creation_qa_certification_authorized(self, api_key: str) -> bool:
        if api_key != self._get_secretsmanager_value(self._API_KEY_AMI_CREATION_QA_CERTIFY):
            raise ValueError("Invalid API Key for AMI QA Certification operation.")

        return True

    def is_ami_creation_mark_for_production_authorized(self, api_key: str) -> bool:
        if api_key != self._get_secretsmanager_value(self._API_KEY_AMI_CREATION_MARK_FOR_PROD):
            raise ValueError("Invalid API Key for AMI Creation Mark for Production Approval operation.")

        return True

    def is_ami_patch_mark_for_production_authorized(self, api_key: str) -> bool:
        if api_key != self._get_secretsmanager_value(self._API_KEY_AMI_PATCH_MARK_FOR_PROD):
            raise ValueError("Invalid API Key for AMI Patch Mark for Production Approval operation.")

        return True

    def is_ami_creation_timeline_authorized(self, api_key: str) -> bool:
        if api_key != self._get_secretsmanager_value(self._API_KEY_AMI_CREATION_TIMELINE):
            raise ValueError("Invalid API Key for AMI Timeline operation.")

        return True

    def is_ami_creation_receiver_authorized(self, api_key: str) -> bool:
        if api_key != self._get_secretsmanager_value(self._API_KEY_AMI_CREATION_RECEIVER):
            raise ValueError("Invalid API Key for AMI Creation Receiver operation.")

        return True

    def is_ami_error_receiver_authorized(self, api_key: str) -> bool:
        if api_key != self._get_secretsmanager_value(self._API_KEY_AMI_ERROR_RECEIVER):
            raise ValueError("Invalid API Key for AMI Error Receiver operation.")

        return True

    def is_ami_patch_receiver_authorized(self, api_key):
        if api_key != self._get_secretsmanager_value(self._API_KEY_AMI_PATCH_RECEIVER):
            raise ValueError("Invalid API Key for AMI Patch Receiver operation.")

        return True

    def is_ami_patch_timeline_authorized(self, api_key: str) -> bool:
        if api_key != self._get_secretsmanager_value(self._API_KEY_AMI_PATCH_TIMELINE):
            raise ValueError("Invalid API Key for AMI Patch Timeline operation.")

        return True

    def is_ami_patch_post_authorized(self, api_key: str) -> bool:
        if api_key != self._get_secretsmanager_value(self._API_KEY_AMI_PATCH_POST):
            raise ValueError("Invalid API Key for AMI Lifecycle Patch POST operation.")

        return True

    def is_ami_patch_put_authorized(self, api_key: str) -> bool:
        if api_key != self._get_secretsmanager_value(self._API_KEY_AMI_PATCH_PUT):
            raise ValueError("Invalid API Key for AMI Lifecycle Patch PUT operation.")

        return True
