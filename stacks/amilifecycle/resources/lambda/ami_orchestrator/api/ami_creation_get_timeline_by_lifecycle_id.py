#!/usr/bin/env python

"""
    ami_creation_get_timeline_by_lifecycle_id.py: 
    lambda handler for the ami creation timeline url:
    GET: https://{api_endpoint}/ami-creation/lifecycles/{lifecycle_id}/timeline?api_key={api_key}"
    See OpenAPI specification (ami-orchestrator-api.yaml) for more details.
"""

import datetime
import json
import logging
import os
import traceback
from os.path import abspath, dirname

import jinja2
import semver
from json2html import *

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

OPERATOR = "AMI_LIFECYCLE_TIMELINE_BY_LIFECYCLE_ID"
ERROR_TEMPLATE_FILE = "lifecycle_event_notification_error.template"
TIMELINE_TEMPLATE_FILE = "ami_creation_timeline.html"
TEMPLATE_LOADER = jinja2.FileSystemLoader(
    searchpath=os.path.join(
        os.path.dirname(__file__), 'templates'
    )
)
TEMPLATE_ENV = jinja2.Environment(
    loader=TEMPLATE_LOADER,
    autoescape=jinja2.select_autoescape(
        default_for_string=True,
        default=True
    )
)
HTML_TABLE_CLASS = "class=\"table table-bordered table-hover table-responsive\""
EVENT_IN_PROGRESS = "EVENT_IN_PROGRESS"
EVENT_IN_PROGRESS_WITH_ERROR = "EVENT_IN_PROGRESS_WITH_ERROR"


def get_event_status(event_name: str, lifecycle_definition: dict) -> str:
    if 'event_in_progress' in lifecycle_definition:
        if 'name' in lifecycle_definition['event_in_progress']:
            if lifecycle_definition['event_in_progress']['name'] == event_name:
                
                if 'error_message' in lifecycle_definition['event_in_progress']:
                    return EVENT_IN_PROGRESS_WITH_ERROR
                
                return EVENT_IN_PROGRESS

    if 'outputs_ami_creation' in lifecycle_definition:
        if 'events' in lifecycle_definition['outputs_ami_creation']:
            for event in lifecycle_definition['outputs_ami_creation']['events']:
                if event['name'] == event_name:
                    return event ['status']
    
    return constants_service.STATUS_NOT_STARTED


def get_event_in_progress(lifecycle_definition: dict) -> str:
    if 'event_in_progress' in lifecycle_definition:
        if 'name' in lifecycle_definition['event_in_progress']:
            if 'error_message' in lifecycle_definition['event_in_progress']:
                return f"{lifecycle_definition['event_in_progress']['name'].replace('_', ' ')} (ERROR - check event for more details)"
            return f"{lifecycle_definition['event_in_progress']['name'].replace('_', ' ')} (IN PROGRESS  - check event for more details)" 
    return "None"           


def handle_event_in_progress(
        event_name: str, 
        event_status: str, 
        lifecycle_definition: dict
    ) -> str:
    description = []

    # handle event in progress
    if event_status == EVENT_IN_PROGRESS or event_status == EVENT_IN_PROGRESS_WITH_ERROR:
        if 'event_in_progress' in lifecycle_definition:
            if 'name' in lifecycle_definition['event_in_progress']:
                if lifecycle_definition['event_in_progress']['name'] == event_name:
                    if 'status_date' in lifecycle_definition['event_in_progress']:
                        description.append(f"<div><h5>Status date: {lifecycle_definition['event_in_progress']['status_date']}</h5></div>")
                    
                    event_in_progress_details = json2html.convert(
                        json=lifecycle_definition['event_in_progress'],
                        table_attributes=HTML_TABLE_CLASS
                    )
                    description.append(f"<div><h5>AMI Details</h5>{event_in_progress_details}</div>")
                    return "".join(description)
    
    return None


def get_ami_build_event_description(
        event_name: str, 
        event_status: str, 
        lifecycle_definition: dict
    ) -> str:
    description = []
    description.append(f"<div><h5>Description</h5><p>{constants_service.EVENT_BUILD_AMI_DESCRIPTION}</p></div>")
    description.append(f"<div><h5>Status: {event_status}</h5></div>")

    # handle event in progress
    event_in_progress_description = handle_event_in_progress(
        event_name, 
        event_status, 
        lifecycle_definition
    )

    if event_in_progress_description is not None:
        description.append(event_in_progress_description)
        return "".join(description)

    # handle completed events
    if 'outputs_ami_creation' in lifecycle_definition:
        if 'events' in lifecycle_definition['outputs_ami_creation']:
            for event in lifecycle_definition['outputs_ami_creation']['events']:
                if event['name'] == event_name:
                    description.append(f"<div><h5>Status date: {event['status_date']}</h5></div>")
                    if event['status'] == constants_service.STATUS_COMPLETED:
                        if 'properties' in event:
                            if 'ami_details' in event['properties']:
                                ami_details_mod = event['properties']['ami_details']
                                for __ami_details in ami_details_mod:
                                    del __ami_details['description']
                                ami_details = json2html.convert(
                                    json=ami_details_mod,
                                    table_attributes=HTML_TABLE_CLASS
                                )
                                description.append(f"<div><h5>AMI Details</h5>{ami_details}</div>")
                            if 'imagebuilder_recipe_components' in event['properties']:
                                components = json2html.convert(
                                    json=event['properties']['imagebuilder_recipe_components'],
                                    table_attributes=HTML_TABLE_CLASS    
                                )
                                description.append(f"<div><h5>AMI Components</h5>{components}</div>")
    
    return "".join(description)


def get_qa_certification_request_event_description(
        event_name: str, 
        event_status: str, 
        lifecycle_definition: dict
    ) -> str:
    description = []
    description.append(f"<div><h5>Description</h5><p>{constants_service.EVENT_QA_CERTIFICATION_REQUEST_DESCRIPTION}</p></div>")
    description.append(f"<div><h5>Status: {event_status}</h5></div>")

    # handle event in progress
    event_in_progress_description = handle_event_in_progress(
        event_name, 
        event_status, 
        lifecycle_definition
    )

    if event_in_progress_description is not None:
        description.append(event_in_progress_description)
        return "".join(description)
                    
    # handle completed events
    if 'outputs_ami_creation' in lifecycle_definition:
        if 'events' in lifecycle_definition['outputs_ami_creation']:
            for event in lifecycle_definition['outputs_ami_creation']['events']:
                if event['name'] == event_name:
                    description.append(f"<div><h5>Status date: {event['status_date']}</h5></div>")
                    if event['status'] == constants_service.STATUS_COMPLETED:
                        if 'properties' in event:
                            event_properties = event['properties']
                            del event_properties['export_image_path']
                            del event_properties['export_presign_s3_url']
                            event_details = json2html.convert(
                                json=event_properties,
                                table_attributes=HTML_TABLE_CLASS    
                            )
                            description.append(f"<div><h5>Properties</h5>{event_details}</div>")
                    
    return "".join(description)


def get_event_description_with_properties(
        event_name: str, 
        event_status: str, 
        event_description: str,
        lifecycle_definition: dict
    ) -> str:
    description = []
    description.append(f"<div><h5>Description</h5><p>{event_description}</p></div>")
    description.append(f"<div><h5>Event Status: {event_status}</h5></div>")
    
    # handle event in progress
    event_in_progress_description = handle_event_in_progress(
        event_name, 
        event_status, 
        lifecycle_definition
    )

    if event_in_progress_description is not None:
        description.append(event_in_progress_description)
        return "".join(description)
                    
    # handle completed events
    if 'outputs_ami_creation' in lifecycle_definition:
        if 'events' in lifecycle_definition['outputs_ami_creation']:
            for event in lifecycle_definition['outputs_ami_creation']['events']:
                if event['name'] == event_name:
                    description.append(f"<div><h5>Status date: {event['status_date']}</h5></div>")
                    if event['status'] == constants_service.STATUS_COMPLETED:
                        if 'properties' in event:
                            properties_details = json2html.convert(
                                json=event['properties'],
                                table_attributes=HTML_TABLE_CLASS
                            )
                            description.append(f"<div><h5>Properties</h5>{properties_details}</div>")

    return "".join(description)


def has_completed_ami_build_event(lifecycle_definition: dict) -> bool:
    if 'outputs_ami_creation' in lifecycle_definition:
        if 'events' in lifecycle_definition['outputs_ami_creation']:
            for event in lifecycle_definition['outputs_ami_creation']['events']:
                if event['name'] == constants_service.EVENT_BUILD_AMI:
                    if event['status'] == constants_service.STATUS_COMPLETED:
                        return True

    return False


def get_current_completed_event(lifecycle_definition: dict) -> bool:
    events = []
    if 'outputs_ami_creation' in lifecycle_definition:
        if 'events' in lifecycle_definition['outputs_ami_creation']:
            for event in lifecycle_definition['outputs_ami_creation']['events']:
                if event['status'] == constants_service.STATUS_COMPLETED:
                    events.append(event)

    if len(events) == 0:
         return "No lifecycle events completed for current AMI Creation execution."

    sorted_list = sorted(
        events,
        key=lambda d: datetime.datetime.strptime(d['status_date'], '%m/%d/%Y, %H:%M:%S').replace(tzinfo=datetime.timezone.utc),
        reverse=True
    )

    return f"{sorted_list[0]['name'].replace('_', ' ')} ({sorted_list[0]['status']})"


def build_template_attributes(
        lifecycle_id:str,
        lifecycle_definition: dict
    ) -> dict:
        # prepare the attributes for the message template
        template_attributes = {}
        template_attributes['operator'] = OPERATOR
        template_attributes['lifecycle_id'] = lifecycle_id
        template_attributes['stack_tag'] = lifecycle_definition['stack_tag']
        template_attributes['current_completed_event'] = get_current_completed_event(lifecycle_definition)
        template_attributes['current_event_in_progress'] = get_event_in_progress(lifecycle_definition)
        template_attributes['product_ver'] = lifecycle_definition['product_ver']
        template_attributes['product_name'] = lifecycle_definition['product_name']
        template_attributes['commit_ref'] = lifecycle_definition['commit_ref']

        # decorate the semver info
        lifecycle_ami_semver_span = ""
        stack_tag_ami_semver = database_service.get_latest_semver_by_stack_tag(lifecycle_definition['stack_tag'])
        if not has_completed_ami_build_event(lifecycle_definition):
            lifecycle_ami_semver = "Awaiting BUILD_AMI event completion"
            lifecycle_ami_semver_span = f'<span>{lifecycle_ami_semver}</span>'
        else:
            lifecycle_ami_semver = ami_details_service.get_latest_ami_semver(definition=lifecycle_definition)
            semver_comparison = semver.compare(lifecycle_ami_semver, stack_tag_ami_semver)
            
            if semver_comparison == -1:
                lifecycle_ami_semver_span = f'<span>{lifecycle_ami_semver}</span><span style="color:red"> (behind StackTag version)</span>'
            elif semver_comparison == 1:
                lifecycle_ami_semver_span = f'<span>{lifecycle_ami_semver}</span><span style="color:blue"> (ahead of StackTag version)</span>'
            else:
                lifecycle_ami_semver_span = f'<span>{lifecycle_ami_semver}</span><span style="color:green"> (equal to StackTag version)</span>'

        template_attributes['lifecycle_ami_semver'] = lifecycle_ami_semver_span
        template_attributes['stack_tag_ami_semver'] = stack_tag_ami_semver

        # ami build
        template_attributes['ami_build'] = {}
        ami_build_status = get_event_status(
                                event_name=constants_service.EVENT_BUILD_AMI,
                                lifecycle_definition=lifecycle_definition
                            )
        template_attributes['ami_build']['title'] = f"AMI Build and Creation - {ami_build_status}"
        ami_build_description = get_ami_build_event_description(
                                    event_name=constants_service.EVENT_BUILD_AMI,
                                    event_status=ami_build_status,
                                    lifecycle_definition=lifecycle_definition
                                )
        template_attributes['ami_build']['description'] = ami_build_description

        # smoke tests
        template_attributes['smoke_tests'] = {}
        smoke_tests_status = get_event_status(
                                event_name=constants_service.EVENT_SMOKE_TESTS_AMI_CREATE,
                                lifecycle_definition=lifecycle_definition
                            )
        template_attributes['smoke_tests']['title'] = f"Smoke Tests - {smoke_tests_status}"
        smoke_tests_description = get_event_description_with_properties(
                                    event_name=constants_service.EVENT_SMOKE_TESTS_AMI_CREATE,
                                    event_description=constants_service.EVENT_SMOKE_TESTS_AMI_CREATE_DESCRIPTION,
                                    event_status=smoke_tests_status,
                                    lifecycle_definition=lifecycle_definition
                                )
        template_attributes['smoke_tests']['description'] = smoke_tests_description

        # vulnerability scans
        template_attributes['vulnerability_scans'] = {}
        vulnerability_scans_status = get_event_status(
                                event_name=constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE,
                                lifecycle_definition=lifecycle_definition
                            )
        template_attributes['vulnerability_scans']['title'] = f"Vulnerability Scans - {vulnerability_scans_status}"
        vulnerability_scans_description = get_event_description_with_properties(
                                    event_name=constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE,
                                    event_description=constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE_DESCRIPTION,
                                    event_status=vulnerability_scans_status,
                                    lifecycle_definition=lifecycle_definition
                                )
        template_attributes['vulnerability_scans']['description'] = vulnerability_scans_description

        # qa certification request
        template_attributes['qa_certification_request'] = {}
        qa_certification_request_status = get_event_status(
                                event_name=constants_service.EVENT_QA_CERTIFICATION_REQUEST,
                                lifecycle_definition=lifecycle_definition
                            )
        template_attributes['qa_certification_request']['title'] = f"QA Certification Request - {qa_certification_request_status}"
        qa_certification_request_description = get_qa_certification_request_event_description(
                                    event_name=constants_service.EVENT_QA_CERTIFICATION_REQUEST,
                                    event_status=qa_certification_request_status,
                                    lifecycle_definition=lifecycle_definition
                                )
        template_attributes['qa_certification_request']['description'] = qa_certification_request_description

        # qa certification response
        template_attributes['qa_certification_response'] = {}
        qa_certification_response_status = get_event_status(
                                event_name=constants_service.EVENT_QA_CERTIFICATION_RESPONSE,
                                lifecycle_definition=lifecycle_definition
                            )
        template_attributes['qa_certification_response']['title'] = f"QA Certification Response - {qa_certification_response_status}"
        qa_certification_response_description = get_event_description_with_properties(
                                    event_name=constants_service.EVENT_QA_CERTIFICATION_RESPONSE,
                                    event_description=constants_service.EVENT_QA_CERTIFICATION_RESPONSE_DESCRIPTION,
                                    event_status=qa_certification_response_status,
                                    lifecycle_definition=lifecycle_definition
                                )
        template_attributes['qa_certification_response']['description'] = qa_certification_response_description

        # mark for production
        template_attributes['mark_for_production'] = {}
        mark_for_production_status = get_event_status(
                                event_name=constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE,
                                lifecycle_definition=lifecycle_definition
                            )
        template_attributes['mark_for_production']['title'] = f"Approve AMI for Production - {mark_for_production_status}"
        mark_for_production_description = get_event_description_with_properties(
                                    event_name=constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE,
                                    event_description=constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE_DESCRIPTION,
                                    event_status=mark_for_production_status,
                                    lifecycle_definition=lifecycle_definition
                                )
        template_attributes['mark_for_production']['description'] = mark_for_production_description

        return template_attributes


def lambda_handler(event, context):
    # read the event to json
    logger.debug(json.dumps(event, indent=2))

    try:
        
        # verify that the api_key query parameter is provided
        if 'queryStringParameters' not in event or 'api_key' not in event['queryStringParameters']:
            raise ValueError(f"api_key is expected as a query parameter but it was not present in the request; {event['rawPath']}")
        
        # if the api_key is not valid an exception will be raised
        security_service.is_ami_creation_timeline_authorized(event['queryStringParameters']['api_key'])
    
        # verify that the {lifecycle-id} path parameter is provided
        if 'lifecycle-id' not in event['pathParameters']:
            raise ValueError(f"lifecycle-id is expected as a path parameter; {event['routeKey']} but it was not present in the request; {event['rawPath']}")
    
        # if the {lifecycle-id} path parameter is provided, process the request
        lifecycle_id = event['pathParameters']['lifecycle-id']
        
        lifecycle_definition = database_service.get_lifecycle_by_lifecycle_id(lifecycle_id)
        
        template_attributes = build_template_attributes(
            lifecycle_id=lifecycle_id,
            lifecycle_definition=lifecycle_definition
        )

        TEMPLATE_FILE = TIMELINE_TEMPLATE_FILE
        template = TEMPLATE_ENV.get_template(TEMPLATE_FILE)
        html_timeline = template.render(vars=template_attributes)
       
        return {
            'statusCode': 200,
            'body': html_timeline,
            'headers': {'Content-Type': 'text/html'}
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
                template_attributes['status_url'] = awsapi_service.get_ami_creation_status_endpoint(lifecycle_definition['lifecycle_id'])
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

        return {
            'statusCode': 500,
            'body': json.dumps(api_error),
            'headers': {'Content-Type': 'application/json'}
        }
