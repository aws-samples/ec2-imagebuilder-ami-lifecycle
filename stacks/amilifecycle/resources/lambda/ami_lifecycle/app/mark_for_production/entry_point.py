#!/usr/bin/env python

"""
    entry_point.py:
    Lambda function that acts as the entry point handler for the AMI Lifecycle
    MARK_FOR_PRODUCTION State Machine.
"""

import datetime
import json
import logging
import traceback

from ..services.constants_service import ConstantsService
from ..services.error_notifier_service import ErrorNotifierService
from ..services.security_service import SecurityService

# constants
OPERATOR = "MARK_FOR_PRODUCTION_EXTRY_POINT"
TEMPLATE_FILE = "state_machine_error.template"

# services
error_notifier_service = ErrorNotifierService()
constants_service = ConstantsService()
security_service = SecurityService()

def lambda_handler(event, context):
    # set logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # print the event details
    logger.debug(json.dumps(event, indent=2))

    # create objects for tracking task progress
    event['mark_for_production_operation'] = {}
    event['mark_for_production_operation']['input'] = {}
    event['mark_for_production_operation']['output'] = {}

    try:

        # validate inputs
        expected_inputs = [ 
            "lifecycle_id", 
            "cfn_stack_name", 
            "ami_id", 
            "ami_name", 
            "ami_region", 
            "ami_owner",
            "operation_type",
            "commit_ref",
            "product_name",
            "product_ver"
        ]
        for expected_input in expected_inputs:
            if expected_input not in event or event[expected_input] == "":
                raise ValueError(f"A valid {expected_input} must be provided as part of the {OPERATOR} state machine input")

        # get details from state machine input
        event['mark_for_production_operation']['input']["lifecycle_id"] = event["lifecycle_id"]
        event['mark_for_production_operation']['input']["cfn_stack_name"] = event["cfn_stack_name"]
        event['mark_for_production_operation']['input']["ami_id"] = event["ami_id"]
        event['mark_for_production_operation']['input']["ami_name"] = event["ami_name"]
        event['mark_for_production_operation']['input']["ami_region"] = event["ami_region"]
        event['mark_for_production_operation']['input']["ami_owner"] = event["ami_owner"]
        event['mark_for_production_operation']['input']["operation_type"] = event["operation_type"]
        event['mark_for_production_operation']['input']["commit_ref"] = event["commit_ref"]
        event['mark_for_production_operation']['input']["product_name"] = event["product_name"]
        event['mark_for_production_operation']['input']["product_ver"] = event["product_ver"]
        event['mark_for_production_operation']['input']["api_key"] = security_service.get_ami_error_receiver_api_key()
        event['mark_for_production_operation']['output']['status'] = constants_service.STATUS_COMPLETED
        event['mark_for_production_operation']['output']['hasError'] = False

        return {
            'statusCode': 200,
            'body': event,
            'headers': {'Content-Type': 'application/json'}
        }

    except Exception as e:
        
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        stack_trace = traceback.format_exc()

        logger.error(f'Error in executing {OPERATOR} operation: {str(e)}')

        event['mark_for_production_operation']['output']['status'] = constants_service.STATUS_ERROR
        event['mark_for_production_operation']['output']['hasError'] = True
        event['mark_for_production_operation']['output']['errorMessage'] = str(e)
        
        # create error payload to send to the api
        error_payload = {}
        error_payload['name'] = constants_service.EVENT_VULNERABILIY_SCANS
        error_payload['status'] = constants_service.STATUS_ERROR
        error_payload['status_date'] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        
        lifecycle_id = "NOT_DEFINED"
        stack_tag = "NOT_DEFINED"

        if 'mark_for_production_operation' in event:
            if 'input' in event['mark_for_production_operation']:
                if 'cfn_stack_name' in event['mark_for_production_operation']['input']:
                    stack_tag = event['mark_for_production_operation']['input']['cfn_stack_name']

        if 'mark_for_production_operation' in event:
            if 'input' in event['mark_for_production_operation']:
                if 'cfn_stack_name' in event['mark_for_production_operation']['input']:
                    lifecycle_id = event['mark_for_production_operation']['input']['lifecycle_id']

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
