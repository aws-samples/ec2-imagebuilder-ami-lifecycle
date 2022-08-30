#!/usr/bin/env python

"""
    ami_selection_utils.py:
    Provides common utility functions for AMI Selection.
"""

import logging

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

config = Config(
    retries=dict(
        max_attempts=1
    )
)

class AmiSelectionUtils:
    """Common utility functions for AMI Selection."""

    @staticmethod
    def get_cloudformation_outputs(
            stack_name: str, 
            region: str
        ) -> dict:

        cfn_resource = boto3.resource("cloudformation", region_name=region, config=config)

        _output_keys = None

        # get stack outputs
        try:
            _stack_outputs = cfn_resource.Stack(stack_name).outputs
            _output_keys = {output["OutputKey"]: output["OutputValue"] for output in _stack_outputs}
        except ClientError as e:
            if e.response['Error']['Code'] == 'ValidationError':
                logger.debug(f"Stack: {stack_name}, not found.")
                raise
            else:
                raise

        return _output_keys
