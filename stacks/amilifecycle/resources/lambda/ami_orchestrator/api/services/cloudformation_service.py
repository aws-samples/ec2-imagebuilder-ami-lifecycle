#!/usr/bin/env python

"""
    cloudformation_service.py:
    service which provides functions to lookup Cloudformation
    stack outputs.
"""

import logging

import boto3

from .constants_service import ConstantsService

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

class CloudformationService:
    """
        Service which provides functions to lookup Cloudformation
        stack outputs.
    """

    constants_service = ConstantsService()

    # boto 3
    client = boto3.client('cloudformation')

    def get_stack_output_value(
            self, 
            cfn_stack_name, 
            output_name
        ) -> str:
        _cfn_lookup_stack = None
        if cfn_stack_name == self.constants_service.CLOUDFORMATION_STACK_IMAGEBUILDER:
            _cfn_lookup_stack = self.constants_service.STACK_NAME_IMAGEBUILDER
        if cfn_stack_name == self.constants_service.CLOUDFORMATION_STACK_AMI_LIFECYCLE:
            _cfn_lookup_stack = self.constants_service.STACK_NAME_AMI_LIFECYCLE

        assert _cfn_lookup_stack is not None

        response = self.client.describe_stacks(
            StackName=_cfn_lookup_stack
        )

        for export in response['Stacks']:
            for output in export['Outputs']:
                if 'OutputKey' in output:
                    if output['OutputKey'] == output_name:
                        return output['OutputValue']

        # unable to find exported value
        raise ValueError(f"Unable to find OutputKey: {output_name} in Cloudformation stack: {_cfn_lookup_stack}")
