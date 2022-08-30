#!/usr/bin/env python

"""
    statemachine_service.py:
    service that provides functionalities and helper methods
    for interacting with AWS Step Functions.
"""

import json
import logging

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# boto3 clients
stepfunctions_client = boto3.client('stepfunctions')

class StateMachineService:
    """
        Service that provides functionalities and helper methods
        for interacting with AWS Step Functions.
    """

    def get_service_name(self) -> str:
        return "statemachine service"


    def execute_state_machine(self, statemachine_arn: str, statemachine_input: str) -> str:
        response = stepfunctions_client.start_execution(
            stateMachineArn=statemachine_arn,
            input=statemachine_input
        )
        return response['executionArn'], response['startDate'].strftime("%m/%d/%Y, %H:%M:%S")

    
    def generate_state_machine_input(self, state_machine_input: dict) -> str:
        # state machine input needs to be an escaped json string
        # after dumping the dict object to json we must explictly escape the quote (")
        # chars in order to produce a valid statemachine input string
        state_machine_input_to_str = json.dumps(
            state_machine_input, 
            separators=(',', ':')
        ).replace('"', '\\"')
        
        # state machine input string must start and end with " so add them before returning
        return f'"{state_machine_input_to_str}"'
            