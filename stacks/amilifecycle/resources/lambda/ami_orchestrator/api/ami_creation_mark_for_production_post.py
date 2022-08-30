#!/usr/bin/env python

"""
    ami_creation_mark_for_production_post.py: 
    lambda handler for the ami creation mark for production url:
    POST: https://{api_endpoint}/ami-creation/lifecycles/{lifecycle-id}/approve
    See OpenAPI specification (ami-orchestrator-api.yaml) for more details.
"""

import datetime
import json
import logging
import os
import random
import string
import traceback

import boto3

from .services.ami_details_service import AmiDetailsService
from .services.aws_api_service import AwsApiService
from .services.constants_service import ConstantsService
from .services.database_service import DatabaseService
from .services.notifier_service import NotifierService
from .services.orchestrator_service import OrchestratorService
from .services.rules_service import RulesService
from .services.security_service import SecurityService
from .services.statemachine_service import StateMachineService
from .services.validator_service import ValidatorService

# set logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

database_service = DatabaseService()
validator_service = ValidatorService()
notifier_service = NotifierService()
awsapi_service = AwsApiService()
security_service = SecurityService()
orchestrator_service = OrchestratorService()
constants_service = ConstantsService()
rules_service = RulesService()
ami_details_service = AmiDetailsService()
state_machine_service = StateMachineService()

# static variable delcarations
OPERATOR = "AMI_CREATION_MARK_FOR_PRODUCTION_APPROVAL_POST"
TEMPLATE_FILE = "lifecycle_event_notification.template"
ERROR_TEMPLATE_FILE = "lifecycle_event_notification_error.template"

# boto3 definitions
sqs_client = boto3.client('sqs')

# env vars
RECEIVER_QUEUE_URL = os.environ['RECEIVER_QUEUE_URL']
MARK_FOR_PRODUCTION_STATEMACHINE_EXPORT = os.environ['MARK_FOR_PRODUCTION_STATEMACHINE_NAME']

def lambda_handler(event, context):
    # read the event to json
    logger.debug(json.dumps(event, indent=2))

    try:

        logger.debug(json.loads(event['body']))
        
        definition = json.loads(event['body'])

        # validate the API key
        if 'api_key' not in definition:
            raise ValueError(f"An api_key must be included as part of the json payload of the request.")
        
        # if the api_key is not valid an exception will be raised
        security_service.is_ami_creation_mark_for_production_authorized(definition['api_key'])

        # validate the structure and basic logic of request 
        # if the request is not valid a ValidationError exception will be raised
        validator_service.validate_lifecycle_mark_for_production_request(definition)

        lifecycle_definition = database_service.get_lifecycle_by_lifecycle_id(
            lifecycle_id=definition['lifecycle_id']
        )

        # sanity check that we do not already have a completed mark for production approval response
        if 'outputs_ami_creation' in lifecycle_definition:
            if 'events' in lifecycle_definition['outputs_ami_creation']:
                for event in lifecycle_definition['outputs_ami_creation']['events']:
                    if event['name'] == constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE:
                        if event['status'] == constants_service.STATUS_COMPLETED:
                            if 'properties' in event and 'approval_status' in event['properties']:
                                if event['properties']['approval_status'] == "APPROVED":
                                    msg = (
                                        "A Mark for Production APPROVED response has already been received " +
                                        "for this AMI lifecycle. Lifecycle events are immutable. There is no " +
                                        "need to attempt to re-approve this AMI."
                                    )
                                    raise ValueError(msg)

        # check if this event can proceed
        rules_service.validate_event_can_proceed_create(
            current_event=constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE,
            defintion=lifecycle_definition
        )

        if definition['approval_status'] == "APPROVED":
            event_status = constants_service.STATUS_COMPLETED

            # grab ami details
            ami_detail = ami_details_service.get_ami_details_for_testing(lifecycle_definition)    

            state_machine_input = {
                "lifecycle_id": lifecycle_definition['lifecycle_id'],
                "operation_type": constants_service.AMI_CREATION,
                "ami_id": ami_detail['image'],
                "ami_name": ami_detail['name'],
                "ami_region": ami_detail['region'],
                "ami_owner": ami_detail['accountId'],
                "ami_semver": ami_detail['ami_semver'],
                "cfn_stack_name": lifecycle_definition['stack_tag'],
                "commit_ref": lifecycle_definition['commit_ref'],
                "product_ver": lifecycle_definition['product_ver'],
                "product_name": lifecycle_definition['product_name']
            }

            formatted_state_machine_input = state_machine_service.generate_state_machine_input(
                                                state_machine_input = state_machine_input
                                            )

            mark_for_production_event_properties = {
                "mark_for_production_ami_id": ami_detail['image'],
                "mark_for_production_ami_name": ami_detail['name'],
                "mark_for_production_ami_region": ami_detail['region'],
                "mark_for_production_ami_owner": ami_detail['accountId']
            }

            # execute the mark for production state machine
            orchestrator_service.execute_state_machine(
                statemachine_input=formatted_state_machine_input,
                definition=lifecycle_definition,
                statemachine_export_name=MARK_FOR_PRODUCTION_STATEMACHINE_EXPORT,
                event_name=constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE,
                event_description=constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE_DESCRIPTION,
                event_properties=mark_for_production_event_properties
            )
        else:
            event_status = constants_service.STATUS_FAILED

            approval_event = {}
            approval_event['name'] = constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE
            approval_event['status_date'] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
            approval_event['status'] = event_status

            if 'properties' in definition:
                approval_event['properties'] = definition['properties']
            else:
                approval_event['properties'] = {}

            approval_event['properties']['approval_status'] = definition['approval_status']
            approval_event['properties']['s3_bucket'] = "NOT_APPLICABLE"
            approval_event['properties']['s3_object_key'] = "NOT_APPLICABLE"
            approval_event['lifecycle_id'] = definition['lifecycle_id']
            approval_event['api_key'] = security_service.get_create_receiver_api_key()

            # create the object to send to the create reciever
            receiver_event = {}
            receiver_event['id'] = ''.join(random.choices(string.ascii_uppercase + string.digits, k=15))
            receiver_event['task_details'] = {}
            receiver_event['task_details']['type'] = 0
            receiver_event['task_details']['value'] = approval_event
            receiver_event['task_details']['task_token'] = ''.join(random.choices(string.ascii_uppercase + string.digits, k=15))

            logger.debug(json.dumps(receiver_event, indent=2))

            # send sns message
            response = sqs_client.send_message(
                QueueUrl=RECEIVER_QUEUE_URL,
                MessageBody=json.dumps(receiver_event, separators=(',', ':'))
            )


        # send the notification
        notifier_service.send_event_notification(
            operator=OPERATOR,
            definition=lifecycle_definition,
            template_file=TEMPLATE_FILE
        )

        notification_channels = []

        for notification in lifecycle_definition['notifications']:
            notification_channels.append({
                "method": notification['method'],
                "target": notification['target']
            })

        response = {
            "lifecycle_id": lifecycle_definition['lifecycle_id'],
            "owner": lifecycle_definition['owner'],
            "creation_date": lifecycle_definition['creation_date'],
            "notification_channels": notification_channels
        }

        return {
            'statusCode': 200,
            'body': json.dumps(response),
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

        try:
            definition
        except NameError:
            # definition is not defined
            template_attributes['lifecycle_id'] = "UNDEFINED"
            template_attributes['stack_tag'] = "UNDEFINED"
            template_attributes['status_url'] = "UNDEFINED"
        else:
            # definition is defined
            if "lifecycle_id" in definition:
                template_attributes['lifecycle_id'] = definition['lifecycle_id']
                template_attributes['status_url'] = awsapi_service.get_ami_status_endpoint(definition['lifecycle_id'])
            else:
                template_attributes['lifecycle_id'] = "UNDEFINED"
                template_attributes['status_url'] = "UNDEFINED"
            
            if "stack_tag" in definition:
                template_attributes['stack_tag'] = definition['stack_tag']
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

        return {
            'statusCode': 500,
            'body': json.dumps(api_error),
            'headers': {'Content-Type': 'application/json'}
        }
