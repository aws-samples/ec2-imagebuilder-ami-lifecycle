#!/usr/bin/env python

"""
    ami_patch_receiver.py: 
    a SQS receiver which responds to AMI Lifecycle AMI Patch callbacks.
"""

import json
import logging
import traceback

import boto3
import semver
import yaml

from ..services.ami_details_service import AmiDetailsService
from ..services.aws_api_service import AwsApiService
from ..services.constants_service import ConstantsService
from ..services.database_service import DatabaseService
from ..services.lifecycle_service import LifecycleService
from ..services.notifier_service import NotifierService
from ..services.orchestrator_service import OrchestratorService
from ..services.security_service import SecurityService
from ..services.validator_service import ValidatorService

# set logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

database_service = DatabaseService()
validator_service = ValidatorService()
notifier_service = NotifierService()
awsapi_service = AwsApiService()
security_service = SecurityService()
ami_details_service = AmiDetailsService()
orchestrator_service = OrchestratorService()
constants_service = ConstantsService()
lifecycle_service = LifecycleService()

# static variable delcarations
OPERATOR = "AMI_PATCH_RECEIVER"
TEMPLATE_FILE = "lifecycle_event_notification.template"
ERROR_TEMPLATE_FILE = "lifecycle_event_notification_error.template"

# boto3
stepfunctions_client = boto3.client('stepfunctions')

def lambda_handler(event, context):
    # read the event to json
    logger.debug(json.dumps(event, indent=2))

    # constants
    task_notifiable_events = [ constants_service.EVENT_PATCH_AMI ]

    try:

        if event and event["Records"]:
            logger.info(f"New event consumed consisting of {len(event['Records'])} record(s).")
            for record in event["Records"]:

                logger.debug(json.loads(record['body']))
                
                record_body = json.loads(record['body'])

                json_request = record_body['task_details']['value']

                logger.debug(json.dumps(json_request, indent=2))

                # validate the API key
                if 'api_key' not in json_request:
                    raise ValueError(f"An api_key must be included as part of the json payload of the request.")
                
                # if the api_key is not valid an exception will be raised
                security_service.is_ami_patch_receiver_authorized(json_request['api_key'])

                if 'lifecycle_id' not in json_request:
                    raise ValueError(f"lifecycle_id must be included as part of the json payload of the request.")
        
                lifecycle_id = json_request['lifecycle_id']

                # validate the structure and basic logic of request 
                # if the request is not valid a ValidationError exception will be raised
                validator_service.validate_lifecycle_definition_patch_receiver_request(json_request)

                # check if we are dealing with an AMI_PATCH event
                # if yes, grab the ami_semver, set it then bump it
                if json_request['name'] == constants_service.EVENT_PATCH_AMI:
                    __definition = database_service.get_lifecycle_by_lifecycle_id(lifecycle_id)
                    current_ami_semver = ami_details_service.get_latest_ami_semver(definition=__definition)
                    bump_type = json_request['semver_bump_type']
                    if bump_type == "MINOR":
                        bumped_ami_semver = semver.VersionInfo.parse(current_ami_semver).bump_minor()
                    else:
                        bumped_ami_semver = semver.VersionInfo.parse(current_ami_semver).bump_patch()
                    if 'properties' in json_request:
                        if 'ami_details' in json_request['properties']:
                            for ami_detail in json_request['properties']['ami_details']:
                                ami_detail['ami_semver'] = semver.format_version(
                                    major=bumped_ami_semver.major,
                                    minor=bumped_ami_semver.minor,
                                    patch=bumped_ami_semver.patch
                                )

                # write the event result to dynamodb
                lifecycle_definition = database_service.update_patch_event_result(lifecycle_id, json_request)

                # tag the ami
                for lifecycle_event in lifecycle_service.get_ami_current_patch_events(lifecycle_definition):
                    if lifecycle_event['name'] == constants_service.EVENT_PATCH_AMI:
                        ami_ancestry = ami_details_service.get_ami_ancestry(lifecycle_definition)
                        json_request['ami_ancestry'] = ami_ancestry
                        ami_details_service.write_tags_for_event_result(
                            lifecycle_id=lifecycle_id,
                            image_name=lifecycle_event['properties']['ami_details'][0]['name'],
                            event_result=json_request
                        )

                # update the AMI Lookup table to reflect the latest lifecycle event
                ami_lookup_entries = ami_details_service.get_ami_lookup_details(
                    definition=lifecycle_definition,
                    lifecycle_type=constants_service.AMI_PATCH,
                    lifecycle_event=json_request['name']
                )
                database_service.update_ami_lookup(ami_lookup_entries=ami_lookup_entries)

                # notification
                lifecycle_status_api = awsapi_service.get_ami_patch_status_endpoint(lifecycle_id)

                # prepare the attributes for the message template
                template_attributes = {}
                template_attributes['operator'] = OPERATOR
                template_attributes['lifecycle_id'] = lifecycle_id
                template_attributes['stack_tag'] = lifecycle_definition['stack_tag']
                template_attributes['status_url'] = lifecycle_status_api
                template_attributes['formatted_event'] = yaml.dump(json_request)
                
                subject = f"{OPERATOR} event for {lifecycle_definition['stack_tag']}"

                # send the notification
                notifier_service.send_notification(
                    subject=subject, 
                    template_name=TEMPLATE_FILE, 
                    template_attributes=template_attributes
                )

                response = {
                    "lifecycle_id": lifecycle_definition['lifecycle_id'],
                    "owner": lifecycle_definition['owner'],
                    "creation_date": lifecycle_definition['creation_date'],
                    "notification_channels": lifecycle_definition['notifications']
                }
                
                receiver_output = {}
                receiver_output['receiver_status'] = constants_service.STATUS_COMPLETED

                if json_request['name'] in task_notifiable_events:
                    # notify the state machines
                    logger.info(f"Sending task success for task ID {record_body['task_token']}")

                    try:
                        stepfunctions_client.send_task_success(
                            taskToken=record_body["task_token"],
                            output=json.dumps(receiver_output)
                        )
                    except stepfunctions_client.exceptions.TaskTimedOut as e:
                        logger.error(f"Task timed out with task token: {record_body['task_token']}")
                        logger.error(str(e))


                # dispatch next event action to the orchestrator service
                orchestrator_service.handle_next_event(
                    api_type=constants_service.AMI_PATCH,
                    definition=database_service.get_lifecycle_by_lifecycle_id(lifecycle_id)
                )

                return {
                    'statusCode': 200,
                    'body': json.dumps(response),
                    'headers': {'Content-Type': 'application/json'}
                }

    except Exception as e:
        
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)

        logger.error(f'{OPERATOR} AMI Lifecycle error: {str(e)}')

        api_error = {"error": str(e)}

        # prepare the attributes for the message template
        template_attributes = {}
        template_attributes['operator'] = OPERATOR

        try:
            lifecycle_definition
        except NameError:
            # definition is not defined
            template_attributes['lifecycle_id'] = "UNDEFINED"
            template_attributes['stack_tag'] = "UNDEFINED"
            template_attributes['status_url'] = "UNDEFINED"
        else:
            # definition is defined
            if "lifecycle_id" in lifecycle_definition:
                template_attributes['lifecycle_id'] = lifecycle_definition['lifecycle_id']
                template_attributes['status_url'] = awsapi_service.get_ami_status_endpoint(lifecycle_definition['lifecycle_id'])
            else:
                template_attributes['lifecycle_id'] = "UNDEFINED"
                template_attributes['status_url'] = "UNDEFINED"
            
            if "stack_tag" in lifecycle_definition:
                template_attributes['stack_tag'] = lifecycle_definition['stack_tag']
            else:
                template_attributes['stack_tag'] = "UNDEFINED"
            
        template_attributes['error'] = api_error

        subject = f"ERROR in {OPERATOR} event for {template_attributes['stack_tag']}"

        # send the notification
        notifier_service.send_notification(
            subject=subject, 
            template_name=ERROR_TEMPLATE_FILE, 
            template_attributes=template_attributes
        )

        if json_request['name'] in task_notifiable_events:
            logger.error(f"Sending task failure for task ID {record_body['task_token']}")    
            
            try:
                stepfunctions_client.send_task_failure(
                    taskToken=record_body["task_token"],
                    cause=str(e)
                )
            except stepfunctions_client.exceptions.TaskTimedOut as e:
                logger.error(f"Task timed out with task token: {record_body['task_token']}")
                logger.error(str(e))

        return {
            'statusCode': 500,
            'body': json.dumps(api_error),
            'headers': {'Content-Type': 'application/json'}
        }
