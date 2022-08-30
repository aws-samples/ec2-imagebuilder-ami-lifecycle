#!/usr/bin/env python

"""
    ami_lifecycle_get_status.py: 
    lambda handler for the ami lifecycle statuses url:
    GET: https://{api_endpoint}/ami-creation/lifecycles/status
    See OpenAPI specification (ami-orchestrator-api.yaml) for more details.
"""

import datetime
import json
import logging
import traceback

from .services.ami_details_service import AmiDetailsService
from .services.aws_api_service import AwsApiService
from .services.constants_service import ConstantsService
from .services.database_service import DatabaseService
from .services.notifier_service import NotifierService
from .services.security_service import SecurityService

# set logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

database_service = DatabaseService()
security_service = SecurityService()
ami_details_service = AmiDetailsService()
notifier_service = NotifierService()
awsapi_service = AwsApiService()
constants_service = ConstantsService()

OPERATOR = "AMI_LIFECYCLE_STATUS"
ERROR_TEMPLATE_FILE = "lifecycle_event_notification_error.template"


def validate_statemachine_timeouts(lifecycle_statuses: list) -> list:

    for lifecycle_status in lifecycle_statuses:
        if 'event_in_progress' in lifecycle_status:
            if 'execution_startdate' in lifecycle_status['event_in_progress']:
                execution_start_date_str = lifecycle_status['event_in_progress']['execution_startdate']
                execution_start_date = datetime.datetime.strptime(
                        execution_start_date_str, 
                        '%m/%d/%Y, %H:%M:%S'
                    ).replace(tzinfo=datetime.timezone.utc)
                compare_time = datetime.datetime.now().astimezone(tz=datetime.timezone.utc)
                time_diff_in_mins = int(abs((compare_time - execution_start_date).total_seconds()) / 60.0)

                logger.debug(f"execution_start_date == {execution_start_date}")
                logger.debug(f"compare_time == {compare_time}")
                logger.debug(f"time_diff_in_mins == {time_diff_in_mins}")

                if time_diff_in_mins > constants_service.STATE_MACHINE_MAX_WAIT_TIME:
                    
                    msg = (
                        "Event in progress has been running for more than " +
                        f"{constants_service.STATE_MACHINE_MAX_WAIT_TIME} minutes. " +
                        "This most likely indicates a state machine timeout or failure. " +
                        f"Please check the executing state machine for more details. " +
                        lifecycle_status['event_in_progress']['execution_arn']
                    )

                    # set the status to indicate a potential time out condition
                    lifecycle_status['event_in_progress']['status'] = constants_service.STATUS_ERROR_EVENT_TIMEOUT
                    lifecycle_status['event_in_progress']['status_date'] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
                    lifecycle_status['event_in_progress']['error_message'] = msg
                    lifecycle_status['event_in_progress']['stack_trace'] = "See error_message"
                    
                    # persist updated event_in_progress
                    lifecycle_status = database_service.update_event_error(
                        lifecycle_id=lifecycle_status['lifecycle_id'], 
                        defintion=lifecycle_status['event_in_progress']
                    )

                    logger.error(msg)

    return database_service.get_lifecycles()


def lambda_handler(event, context):
    # read the event to json
    logger.debug(json.dumps(event, indent=2))

    try:
        
        # verify that the api_key query parameter is provided
        if 'queryStringParameters' not in event or 'api_key' not in event['queryStringParameters']:
            raise ValueError(f"api_key is expected as a query parameter but it was not present in the request; {event['rawPath']}")
        
        # if the api_key is not valid an exception will be raised
        security_service.is_ami_creation_status_authorized(event['queryStringParameters']['api_key'])
    
        lifecycles = validate_statemachine_timeouts(
            lifecycle_statuses=database_service.get_lifecycles()
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps(lifecycles, sort_keys=True),
            'headers': {'Content-Type': 'application/json'}
        }
        
    except ValueError as e:
        logger.error(f'{OPERATOR} AMI Lifecycle error: {str(e)}')

        api_error = {"error": str(e)}

        return {
            'statusCode': 500,
            'body': json.dumps(api_error),
            'headers': {'Content-Type': 'application/json'}
        }

    except Exception as e:
        
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)

        logger.error(f'{OPERATOR} AMI Lifecycle error: {str(e)}')

        api_error = {"error": str(e)}

        # prepare the attributes for the message template
        template_attributes = {}
        template_attributes['operator'] = OPERATOR
        template_attributes['lifecycle_id'] = "MULTIPLE_IDS"

        if 'queryStringParameters' in event and 'stack_tag' in event['queryStringParameters']:
            template_attributes['stack_tag'] = event['queryStringParameters']['stack_tag']
        else:
            template_attributes['stack_tag'] = "UNDEFINED"

        template_attributes['error'] = api_error
        template_attributes['status_url'] = "MULTIPLE_URLS"

        subject = f"ERROR in {OPERATOR} event for {template_attributes['stack_tag']}"

        # send the notification
        notifier_service.send_notification(
            subject=subject, 
            template_name=ERROR_TEMPLATE_FILE, 
            template_attributes=template_attributes
        )

        return {
            'statusCode': 500,
            'body': json.dumps(api_error),
            'headers': {'Content-Type': 'application/json'}
        }
