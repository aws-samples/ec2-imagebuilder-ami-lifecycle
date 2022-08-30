#!/usr/bin/env python

"""
    aws_api_service.py:
    service which interacts with API Gateway to obtain
    AMI Orchestrator API endpoints.
"""

import logging
import os

import boto3

from ..services.security_service import SecurityService

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

class AwsApiService:
    """
        Service which interacts with API Gateway to obtain
        AMI Orchestrator API endpoints.
    """

    client_apigatewayv2 = boto3.client('apigatewayv2')

    API_NAME = os.environ['API_NAME']
    API_STAGE_NAME = os.environ['API_STAGE_NAME']

    security_service = SecurityService()
    
    def _get_api_by_name(self, api_name: str) -> str:
        get_apis = self.client_apigatewayv2.get_apis()
        for api in get_apis['Items']:
            if api['Name'] == api_name:
                return api['ApiId']
    
        return None

    def _get_api_endpoint(self) -> str:
        
        if self._get_api_by_name(self.API_NAME) is not None:
        
            response = self.client_apigatewayv2.get_api(
                ApiId=self._get_api_by_name(self.API_NAME)
            )
    
            return f"{response['ApiEndpoint']}/{self.API_STAGE_NAME}"
            
        return f"No endpoint found for API Gateway with name {self.API_NAME}"


    # REST API Paths
    def get_base_endpoint(self) -> str:
        return self._get_api_endpoint()

    def get_ami_status_endpoint(self, lifecycle_id: str) -> str:
        api_endpoint = self._get_api_endpoint()
        api_key = self.security_service.get_status_api_key()
        return f"{api_endpoint}/ami-creation/lifecycles/{lifecycle_id}/status?api_key={api_key}"

    def get_ami_patch_status_endpoint(self, lifecycle_id: str) -> str:
        api_endpoint = self._get_api_endpoint()
        api_key = self.security_service.get_status_api_key()
        return f"{api_endpoint}/ami-patch/lifecycles/{lifecycle_id}/status?api_key={api_key}"

    def get_ami_creation_timeline_endpoint(self, lifecycle_id: str) -> str:
        api_endpoint = self._get_api_endpoint()
        api_key = self.security_service.get_create_timeline_api_key()
        return f"{api_endpoint}/ami-creation/lifecycles/{lifecycle_id}/timeline?api_key={api_key}"

    def get_ami_patch_timeline_endpoint(self, lifecycle_id: str) -> str:
        api_endpoint = self._get_api_endpoint()
        api_key = self.security_service.get_patch_timeline_api_key()
        return f"{api_endpoint}/ami-patch/lifecycles/{lifecycle_id}/timeline?api_key={api_key}"
