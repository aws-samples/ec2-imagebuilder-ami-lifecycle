#!/usr/bin/env python

"""
    api-cli.py: a Python CLI (Command Line Interface) which simplifies the use of 
                the Orchestrator API and allow API consumers to focus on the business 
                functionality of the AMI lifecycle rather than the low-level usage of the API.
                
    See the README.md for further information.
"""

import argparse
import json
import logging
import os
import re
import sys
import traceback

import boto3
import requests
from git import Repo
from simple_term_menu import TerminalMenu

# boto 3
secretsmanager_client = boto3.client('secretsmanager')
cloudformation_client = boto3.client('cloudformation')
s3_client = boto3.client('s3')

##########################################################
# <START> Common functions shared between batch 
#         and interactive modes
##########################################################

OPERATION_AMI_CREATE = "AMI_CREATE"
OPERATION_AMI_CREATE_UPDATE = "AMI_CREATE_UPDATE"
OPERATION_AMI_PATCH = "AMI_PATCH"
OPERATION_AMI_PATCH_UPDATE = "AMI_PATCH_UPDATE"
OPERATION_AMI_GET_STATUS_BY_LIFECYCLE_ID = "AMI_GET_STATUS_BY_LIFECYCLE_ID"
OPERATION_AMI_GET_STATUSES = "AMI_GET_STATUSES"
OPERATION_AMI_QA_CERTIFICATION = "AMI_QA_CERTIFICATION"
OPERATION_AMI_APPROVAL_CREATE = "AMI_APPROVAL_CREATE"
OPERATION_AMI_APPROVAL_PATCH = "AMI_APPROVAL_PATCH"
OPERATION_AMI_TIMELINE_CREATE = "AMI_TIMELINE_CREATE"
OPERATION_AMI_TIMELINE_PATCH = "AMI_TIMELINE_PATCH"

OPERATION_TYPE_CREATE = "CREATE_AMI_OP"
OPERATION_TYPE_PATCH = "PATCH_AMI_OP"

CLI_MODE_INTERACTIVE="UI"
CLI_MODE_BATCH="BATCH"

CLI_EVENT_BUILD_ONLY = "AMI_BUILD_ONLY"
CLI_EVENT_SMOKE_TESTS = "SMOKE_TESTS"
CLI_EVENT_VULNERABILITY_SCANS = "VULNERABILITY_SCANS"
CLI_EVENT_QA_CERTIFY_REQUEST = "QA_CERTIFICATION_REQUEST"
CLI_EVENT_QA_CERTIFY_RESPONSE = "QA_CERTIFICATION_RESPONSE"
CLI_EVENT_MARK_FOR_PRODUCTION_CREATE = "MARK_FOR_PRODUCTION_CREATE"
CLI_EVENT_MARK_FOR_PRODUCTION_PATCH = "MARK_FOR_PRODUCTION_PATCH"
CLI_EVENT_PATCH_ONLY = "AMI_PATCH_ONLY"

QA_CERTIFICATION_STATUS_CERTIFIED = "CERTIFIED"
QA_CERTIFICATION_STATUS_FAILED = "FAILED"

PRODUCTION_APPROVAL_STATUS_APPROVED = "APPROVED"
PRODUCTION_APPROVAL_STATUS_FAILED = "FAILED"

SEMVER_BUMP_TYPE_MINOR = "MINOR"
SEMVER_BUMP_TYPE_PATCH = "PATCH"

ARG_SEPERATOR = "::"

# set logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger()


def get_git_commit_ref() -> str:
    # current git sha1 hash
    return Repo(search_parent_directories=True).head.object.hexsha


def get_api_endpoint() -> str:

    output_key = "amiOrchestratorApiGatewayUrl"
    stack_name = "AmiLifecycle"

    response = cloudformation_client.describe_stacks(
        StackName=stack_name
    )

    for export in response['Stacks']:
        for output in export['Outputs']:
            if 'OutputKey' in output:
                if output['OutputKey'] == f"{output_key}":
                    return output['OutputValue']

    # unable to find exported value
    raise ValueError(f"Unable to find OutputKey: {output_key} in Cloudformation stack: {stack_name}")


def get_patch_component_bucket() -> str:

    output_key = "amiLifecyclePatchComponentBucket"
    stack_name = "AmiLifecycle"

    response = cloudformation_client.describe_stacks(
        StackName=stack_name
    )

    for export in response['Stacks']:
        for output in export['Outputs']:
            if 'OutputKey' in output:
                if output['OutputKey'] == f"{output_key}":
                    return output['OutputValue']

    # unable to find exported value
    raise ValueError(f"Unable to find OutputKey: {output_key} in Cloudformation stack: {stack_name}")


def get_api_key(operation) -> str:
    _API_KEY_SECRET_BASE_PATH=f"/ami-lifecycle/api-keys"
    _API_KEY_AMI_CREATION_POST = f"{_API_KEY_SECRET_BASE_PATH}/ami_creation_post_api_key"
    _API_KEY_AMI_CREATION_PUT = f"{_API_KEY_SECRET_BASE_PATH}/ami_creation_put_api_key"
    _API_KEY_AMI_CREATION_STATUS = f"{_API_KEY_SECRET_BASE_PATH}/ami_creation_status_api_key"
    _API_KEY_AMI_CREATION_QA_CERTIFICATION = f"{_API_KEY_SECRET_BASE_PATH}/ami_creation_qa_certification_key"
    _API_KEY_AMI_CREATION_MARK_FOR_PRODUCTION = f"{_API_KEY_SECRET_BASE_PATH}/ami_creation_mark_for_production_key"
    _API_KEY_AMI_PATCH_MARK_FOR_PRODUCTION = f"{_API_KEY_SECRET_BASE_PATH}/ami_patch_mark_for_production_key"
    _API_KEY_AMI_CREATION_TIMELINE = f"{_API_KEY_SECRET_BASE_PATH}/ami_creation_timeline_api_key"
    _API_KEY_AMI_PATCH_POST = f"{_API_KEY_SECRET_BASE_PATH}/ami_patch_post_api_key"
    _API_KEY_AMI_PATCH_PUT = f"{_API_KEY_SECRET_BASE_PATH}/ami_patch_put_api_key"
    _API_KEY_AMI_PATCH_TIMELINE = f"{_API_KEY_SECRET_BASE_PATH}/ami_patch_timeline_api_key"


    if operation == OPERATION_AMI_CREATE:
        response = secretsmanager_client.get_secret_value(
            SecretId=_API_KEY_AMI_CREATION_POST,
        )
        return response['SecretString']
    
    if operation == OPERATION_AMI_CREATE_UPDATE:
        response = secretsmanager_client.get_secret_value(
            SecretId=_API_KEY_AMI_CREATION_PUT,
        )
        return response['SecretString']

    if operation == OPERATION_AMI_GET_STATUS_BY_LIFECYCLE_ID or operation == OPERATION_AMI_GET_STATUSES:
        response = secretsmanager_client.get_secret_value(
            SecretId=_API_KEY_AMI_CREATION_STATUS,
        )
        return response['SecretString']

    if operation == OPERATION_AMI_QA_CERTIFICATION:
        response = secretsmanager_client.get_secret_value(
            SecretId=_API_KEY_AMI_CREATION_QA_CERTIFICATION,
        )
        return response['SecretString']

    if operation == OPERATION_AMI_APPROVAL_CREATE:
        response = secretsmanager_client.get_secret_value(
            SecretId=_API_KEY_AMI_CREATION_MARK_FOR_PRODUCTION,
        )
        return response['SecretString']

    if operation == OPERATION_AMI_APPROVAL_PATCH:
        response = secretsmanager_client.get_secret_value(
            SecretId=_API_KEY_AMI_PATCH_MARK_FOR_PRODUCTION,
        )
        return response['SecretString']

    if operation == OPERATION_AMI_TIMELINE_CREATE:
        response = secretsmanager_client.get_secret_value(
            SecretId=_API_KEY_AMI_CREATION_TIMELINE,
        )
        return response['SecretString']

    if operation == OPERATION_AMI_PATCH:
        response = secretsmanager_client.get_secret_value(
            SecretId=_API_KEY_AMI_PATCH_POST,
        )
        return response['SecretString']
    
    if operation == OPERATION_AMI_PATCH_UPDATE:
        response = secretsmanager_client.get_secret_value(
            SecretId=_API_KEY_AMI_PATCH_PUT,
        )
        return response['SecretString']

    if operation == OPERATION_AMI_TIMELINE_PATCH:
        response = secretsmanager_client.get_secret_value(
            SecretId=_API_KEY_AMI_PATCH_TIMELINE,
        )
        return response['SecretString']


def generate_ami_create_request(
        operation: str,
        stack_tag: str,
        owner: str,
        notifications: list,
        smoke_tests: bool,
        vulnerability_scans: bool,
        qa_certification: bool,
        properties: dict,
        lifecycle_id: str,
        product_ver: str,
        product_name: str,
        commit_ref: str
    ) -> dict:

    create_request = {
        "api_key": get_api_key(operation),
        "stack_tag": stack_tag,
        "owner": owner,
        "notifications": notifications,
        "events": [
            {
                "name": "BUILD_AMI",
                "enabled": True if operation == OPERATION_AMI_CREATE else False
            },
            {
                "name": "SMOKE_TESTS_AMI_CREATE",
                "enabled": smoke_tests
            },
            {
                "name": "VULNERABILIY_SCANS_AMI_CREATE",
                "enabled": vulnerability_scans
            },
            {
                "name": "QA_CERTIFICATION_REQUEST",
                "enabled": qa_certification
            }
        ]
    }

    if properties is not None:
        create_request['properties'] = properties

    if lifecycle_id is not None:
        create_request['lifecycle_id'] = lifecycle_id

    if product_ver is not None:
        create_request['product_ver'] = product_ver

    if product_name is not None:
        create_request['product_name'] = product_name

    if commit_ref is not None:
        create_request['commit_ref'] = get_git_commit_ref()

    return create_request


def generate_ami_patch_request(
        operation: str,
        stack_tag: str,
        owner: str,
        notifications: list,
        smoke_tests: bool,
        vulnerability_scans: bool,
        properties: dict,
        patch_component_url: str,
        patch_change_description: str,
        semver_bump_type: str,
        commit_ref: str,
        lifecycle_id: str
    ) -> dict:

    if operation == OPERATION_AMI_PATCH:
        if properties is None:
            properties = {}

        # verify that the patch component exists and upload it to s3
        if not os.path.exists(patch_component_url):
            raise ValueError(
                f" The provided patch_component_url: {patch_component_url} does not exist."
            )

        # patch_component_url exists, upload to s3
        patch_component_bucket = get_patch_component_bucket()
        patch_component_filename = os.path.basename(patch_component_url)
        s3_client.upload_file(
            patch_component_url,
            patch_component_bucket,
            f"{lifecycle_id}/{patch_component_filename}"
        )
        
        properties['patch_component_url'] = f"s3://{patch_component_bucket}/{lifecycle_id}/{patch_component_filename}"
        properties['patch_change_description'] = patch_change_description
        properties['semver_bump_type'] = semver_bump_type
        
    patch_request = {
        "api_key": get_api_key(operation),
        "stack_tag": stack_tag,
        "owner": owner,
        "notifications": notifications,
        "events": [
            {
                "name": "PATCH_AMI",
                "enabled": True if operation == OPERATION_AMI_PATCH else False
            },
            {
                "name": "SMOKE_TESTS_AMI_PATCH",
                "enabled": smoke_tests
            },
            {
                "name": "VULNERABILITY_SCANS_AMI_PATCH",
                "enabled": vulnerability_scans
            }
        ],
        "properties": properties
    }

    if lifecycle_id is not None:
        patch_request['lifecycle_id'] = lifecycle_id

    patch_request['commit_ref'] = commit_ref if commit_ref is not None else ""

    return patch_request


def generate_ami_qa_certification_request(
        operation: str,
        stack_tag: str,
        certification_status: str,
        properties: dict,
        lifecycle_id: str = None
    ) -> dict:

    qa_certify_request = {
        "api_key": get_api_key(operation),
        "stack_tag": stack_tag,
        "certification_status": certification_status
    }

    if lifecycle_id is not None:
        qa_certify_request['lifecycle_id'] = lifecycle_id

    if properties is not None:
        qa_certify_request['properties'] = properties


    return qa_certify_request


def generate_ami_approval_request(
        operation: str,
        stack_tag: str,
        approval_status: str,
        properties: dict,
        lifecycle_id: str = None
    ) -> dict:

    ami_approval_request = {
        "api_key": get_api_key(operation),
        "stack_tag": stack_tag,
        "approval_status": approval_status
    }

    if lifecycle_id is not None:
        ami_approval_request['lifecycle_id'] = lifecycle_id

    if properties is not None:
        ami_approval_request['properties'] = properties


    return ami_approval_request


def get_status_api_endpoint(
        lifecycle_id: str,
        operation_type: str
    ) -> str:
    
    api_endpoint = f"{get_api_endpoint()}/ami-creation/lifecycles/{lifecycle_id}/status"
    api_key = get_api_key(OPERATION_AMI_GET_STATUS_BY_LIFECYCLE_ID)

    if operation_type == OPERATION_AMI_PATCH:
        api_endpoint = f"{get_api_endpoint()}/ami-patch/lifecycles/{lifecycle_id}/status"
        api_key = get_api_key(OPERATION_AMI_GET_STATUS_BY_LIFECYCLE_ID)
  
    return f"{api_endpoint}?api_key={api_key}"

def get_statuses_api_endpoint(
        operation_type: str
    ) -> str:
    
    api_endpoint = f"{get_api_endpoint()}/ami-creation/lifecycles/status"
    api_key = get_api_key(OPERATION_AMI_GET_STATUSES)

    if operation_type == OPERATION_AMI_PATCH:
        api_endpoint = f"{get_api_endpoint()}/ami-patch/lifecycles/status"
        api_key = get_api_key(OPERATION_AMI_GET_STATUSES)
  
    return f"{api_endpoint}?api_key={api_key}"


def get_timeline_api_endpoint(
        lifecycle_id: str,
        operation_type: str = OPERATION_TYPE_CREATE
    ) -> str:
    if operation_type == OPERATION_TYPE_CREATE:
        api_endpoint = f"{get_api_endpoint()}/ami-creation/lifecycles/{lifecycle_id}/timeline"
        api_key = get_api_key(OPERATION_AMI_TIMELINE_CREATE)
    if operation_type == OPERATION_TYPE_PATCH:
        api_endpoint = f"{get_api_endpoint()}/ami-patch/lifecycles/{lifecycle_id}/timeline"
        api_key = get_api_key(OPERATION_AMI_TIMELINE_PATCH)
    
    return f"{api_endpoint}?api_key={api_key}"


##########################################################
# </END> Common functions shared between batch 
#         and interactive modes
##########################################################


##########################################################
# <START> Interactive mode (UI) specific functions
##########################################################

UI_CONFIG_FILE = 'cli-config.json'
RELATIVE_CLI_DIR = '/stacks/amilifecycle/resources/cli'

def get_stack_tag() -> str:
    _STACK_TAG = None
    try:
        current_path = os.getcwd()
        repo_root = current_path.replace(RELATIVE_CLI_DIR, "")
        repo = Repo(path=repo_root)
        branch_name = repo.active_branch.name

        # Create a "slug" from the branch name, by replacing all
        # non-alphanumeric characters in the branch name with a dash.
        _STACK_TAG = re.sub(
            r"""[^a-zA-Z0-9-]""",
            r"""-""",
            branch_name
        ).lower()
    except Exception as e:
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        logger.error(f"ERROR attempting to get stack tag: {str(e)}")
        print("Unable to determine the stack tag for this request.")
        msg = (
            "In order to auto-determine the stack tag, " +
            f"the cli application should be executed from the directory: {RELATIVE_CLI_DIR} " +
            "Proceeding with default stack tag."
        )
        print(msg)
        if _STACK_TAG is None:
            _STACK_TAG = "default"
    finally:
        return _STACK_TAG


def get_cli_config() -> None:
    if os.path.exists(UI_CONFIG_FILE):
        with open(UI_CONFIG_FILE, 'r') as config_file:
            data = config_file.read()

        return json.loads(data)

    logger.error(f"Confile file {UI_CONFIG_FILE} does not exist.")
    print(f"In order to use interactive mode, a {UI_CONFIG_FILE} is required.")
    print(f"An example {UI_CONFIG_FILE} config file is shown below for reference.")
    print("")
    example_config = {
        "owner": "damiamcd",
        "notifications": [
            {
                "method": "EMAIL",
                "target": "user@domain.com"
            }
        ],
        "properties": {
            "GITLAB_PIPLEINE_URL": "https://gitlab.com/pipelines/123456"
        }
    }
    print(json.dumps(example_config, indent=2))


def yes_or_no(question) -> None:
    while "the answer is invalid":
        reply = str(input(question+' (y/n/q): ')).lower().strip()
        if reply[:1] == 'y':
            return True
        if reply[:1] == 'n':
            return display_menus()
        if reply[:1] == 'q':
            sys.exit(0)


def get_status_url_util( 
        mode: str, 
        lifecycle_id: str,
        operation_type: str
    ) -> None:

    if mode == CLI_MODE_INTERACTIVE:
        print("######################################")
        print("")
        lifecycle_id = str(input("Enter the lifecycle_id:\n"))
        print("")
        print("You can check the status of this AMI lifecycle request at any time via the link below:")
        print("")
        print(get_status_api_endpoint(lifecycle_id, operation_type))
        print("")
        yes_or_no("Do you want to exit?")
    else:
        print(get_status_api_endpoint(lifecycle_id, operation_type))


def get_statuses_url_util( 
        operation_type: str
    ) -> None:
    print(get_statuses_api_endpoint(operation_type))


def get_timeline_url_util( 
        mode: str, 
        operation_type: str = OPERATION_TYPE_CREATE,
        lifecycle_id: str = None
    ) -> None:

    if mode == CLI_MODE_INTERACTIVE:
        print("######################################")
        print("")
        lifecycle_id = str(input("Enter the lifecycle_id:\n"))
        print("")
        print("You can check the timeline of this AMI lifecycle request at any time via the link below:")
        print("")
        print(get_timeline_api_endpoint(lifecycle_id, operation_type))
        print("")
        yes_or_no("Do you want to exit?")
    else:
        print(get_timeline_api_endpoint(lifecycle_id, operation_type))


def print_api_response(
        response, 
        mode,
        operation_type: str
    ) -> None:
    if mode == CLI_MODE_INTERACTIVE:
        print("######################################")
        print("API Response details:")
        print("")
        print(f"Api HTTP Status response: {response.status_code}")
        print("")
        json_response = response.json()
        print(json.dumps(json_response, indent=2))
        if 'lifecycle_id' in json_response:
            print("")
            print("Below is the lifecycle_id for this request, you will need this for subsequent API operations")
            print("")
            print(json_response['lifecycle_id'])
            print("")
            print("You can check the status of this AMI lifecycle request at any time via the link below:")
            print("")
            print(get_status_api_endpoint(json_response['lifecycle_id'], operation_type))
            print("")
            yes_or_no("Do you want to exit?")
        else:
            print("")
            print("Unexpected JSON reponse, check output for errors")
            print("")
    else:
        json_response = response.json()
        if 'lifecycle_id' in json_response:
            print(json_response['lifecycle_id'])
        else:
            print("")
            print("Unexpected JSON reponse, check output for errors")
            print("")


def process_ami_create_request(
    operation: str,
    selected_items: list) -> None:

    print("######################################")
    print("")
    print(f"Selected items: {selected_items}")

    ui_config = get_cli_config()
    stack_tag=get_stack_tag()

    if operation == OPERATION_AMI_CREATE:
        print("######################################")
        print("")
        product_ver = str(input("Enter the product version:\n"))
        print("")
        product_name = str(input("Enter the product name:\n"))
        print("")
        ami_request = generate_ami_create_request(
            operation=operation,
            stack_tag=stack_tag,
            owner=ui_config['owner'],
            properties=None if 'properties' not in ui_config else ui_config['properties'],
            notifications=ui_config['notifications'],
            smoke_tests=True if "Smoke Tests" in selected_items else False,
            vulnerability_scans=True if "Vulnerability Scans" in selected_items else False,
            qa_certification=True if "QA Certification" in selected_items else False,
            product_name=product_name,
            product_ver=product_ver,
            commit_ref=get_git_commit_ref(),
            lifecycle_id=None
        )
    elif operation == OPERATION_AMI_CREATE_UPDATE:
        print("######################################")
        print("")
        lifecycle_id = str(input("Enter the lifecycle_id:\n"))
        print("")

        ami_request = generate_ami_create_request(
            operation=operation,
            stack_tag=stack_tag,
            owner=ui_config['owner'],
            properties=None if 'properties' not in ui_config else ui_config['properties'],
            notifications=ui_config['notifications'],
            smoke_tests=True if "Smoke Tests" in selected_items else False,
            vulnerability_scans=True if "Vulnerability Scans" in selected_items else False,
            qa_certification=True if "QA Certification" in selected_items else False,
            lifecycle_id=lifecycle_id,
            product_name=None,
            product_ver=None,
            commit_ref=None
        )


    print("")
    print("Json Request")
    print(json.dumps(ami_request, indent=2))

    api_endpoint = f"{get_api_endpoint()}/ami-creation/lifecycles"
    print("")
    http_method="POST" if operation == OPERATION_AMI_CREATE else "PUT"
    print(f"{http_method} api_endpoint: {api_endpoint}")

    print("")
    yes_or_no("Do you want to proceed with the API request?")

    try:
        if operation == OPERATION_AMI_CREATE:
            response = requests.post(
                url=api_endpoint, 
                json=ami_request
            )
        elif operation == OPERATION_AMI_CREATE_UPDATE:
            response = requests.put(
                url=api_endpoint, 
                json=ami_request
            )  

        print_api_response(response, CLI_MODE_INTERACTIVE, OPERATION_AMI_CREATE)
    except Exception as e:
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        logger.error(f"Error in API invocation: {http_method} api_endpoint: {api_endpoint}")
        print(str(e))


def process_ami_patch_request(
        operation: str, 
        selected_items: list
    ) -> None:

    print("######################################")
    print("")
    print(f"Selected items: {selected_items}")

    ui_config = get_cli_config()
    stack_tag=get_stack_tag()

    if operation == OPERATION_AMI_PATCH:
        print("######################################")
        print("")
        lifecycle_id = str(input("Enter the lifecycle_id:\n"))
        print("")
        print("")
        patch_component_url = str(input("Enter the patch component S3 url:\n"))
        print("")
        print("")
        patch_change_description = str(input("Enter the patch change description:\n"))
        print("")
        print("")
        semver_bump_type = str(input(f"Enter the patch semantic version bump type: {SEMVER_BUMP_TYPE_MINOR} or {SEMVER_BUMP_TYPE_PATCH}\n"))
        if semver_bump_type not in [SEMVER_BUMP_TYPE_MINOR, SEMVER_BUMP_TYPE_PATCH]:
            raise ValueError(f"semver_bump_type must be either {SEMVER_BUMP_TYPE_MINOR} or {SEMVER_BUMP_TYPE_PATCH}")
        print("")

        ami_request = generate_ami_patch_request(
            operation=operation,
            stack_tag=stack_tag,
            owner=ui_config['owner'],
            properties=None if 'properties' not in ui_config else ui_config['properties'],
            notifications=ui_config['notifications'],
            smoke_tests=True if "Smoke Tests" in selected_items else False,
            vulnerability_scans=True if "Vulnerability Scans" in selected_items else False,
            lifecycle_id=lifecycle_id,
            patch_component_url=patch_component_url,
            patch_change_description=patch_change_description,
            semver_bump_type=semver_bump_type,
            commit_ref=get_git_commit_ref()
        )
    elif operation == OPERATION_AMI_PATCH_UPDATE:
        print("######################################")
        print("")
        lifecycle_id = str(input("Enter the lifecycle_id:\n"))
        print("")

        ami_request = generate_ami_patch_request(
            operation=operation,
            stack_tag=stack_tag,
            owner=ui_config['owner'],
            properties=None if 'properties' not in ui_config else ui_config['properties'],
            notifications=ui_config['notifications'],
            smoke_tests=True if "Smoke Tests" in selected_items else False,
            vulnerability_scans=True if "Vulnerability Scans" in selected_items else False,
            lifecycle_id=lifecycle_id,
            patch_component_url=None,
            patch_change_description=None,
            semver_bump_type=None,
            commit_ref=None
        )


    print("")
    print("Json Request")
    print(json.dumps(ami_request, indent=2))
    api_endpoint = f"{get_api_endpoint()}/ami-patch/lifecycles"
    print("")
    http_method="POST" if operation == OPERATION_AMI_PATCH else "PUT"
    print(f"{http_method} api_endpoint: {api_endpoint}")

    print("")
    yes_or_no("Do you want to proceed with the API request?")

    try:
        if operation == OPERATION_AMI_PATCH:
            response = requests.post(
                url=api_endpoint, 
                json=ami_request
            )
        elif operation == OPERATION_AMI_PATCH_UPDATE:
            response = requests.put(
                url=api_endpoint, 
                json=ami_request
            )  

        print_api_response(response, CLI_MODE_INTERACTIVE, OPERATION_AMI_PATCH)
    except Exception as e:
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        logger.error(f"Error in API invocation: {http_method} api_endpoint: {api_endpoint}")
        print(str(e))


def process_qa_certification_request(mode: str) -> None:

    try:

        stack_tag=get_stack_tag()

        print("######################################")
        print("")
        lifecycle_id = str(input("Enter the lifecycle_id:\n"))
        print("")
        certification_status = str(
            input(
                f"Enter the certification status ({QA_CERTIFICATION_STATUS_CERTIFIED} or {QA_CERTIFICATION_STATUS_FAILED}):\n"
            )
        )
        if certification_status not in [ QA_CERTIFICATION_STATUS_CERTIFIED, QA_CERTIFICATION_STATUS_FAILED ]:
            msg = f"certification_status must be {QA_CERTIFICATION_STATUS_CERTIFIED} or {QA_CERTIFICATION_STATUS_FAILED}"
            logger.error(msg)
            raise ValueError(msg)

        # example_properties = {
        #     "qa_jira_ref": "https://jira.com/browse/12345",
        #     "qa_owner": "CLI Utility",
        #     "qa_comment": "QA Certification via the CLI Utility"
        # }
        example_properties = None

        qa_certify_request = generate_ami_qa_certification_request(
            operation=OPERATION_AMI_QA_CERTIFICATION,
            stack_tag=stack_tag,
            certification_status=certification_status,
            properties=example_properties,
            lifecycle_id=lifecycle_id
        )

        print("")
        print("Json Request")
        print(json.dumps(qa_certify_request, indent=2))

        api_endpoint = f"{get_api_endpoint()}/ami-creation/lifecycles/{lifecycle_id}/certify"
        print("")
        http_method="POST"
        print(f"{http_method} api_endpoint: {api_endpoint}")

        print("")
        yes_or_no("Do you want to proceed with the API request?")

        response = requests.post(
            url=api_endpoint, 
            json=qa_certify_request
        )

        print_api_response(response, CLI_MODE_INTERACTIVE, OPERATION_AMI_CREATE)

    except Exception as e:
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        logger.error(f"Error in API invocation: {http_method} api_endpoint: {api_endpoint}")
        print(str(e))


def process_mark_for_production_request(mode: str, operation_type: str) -> None:

    try:

        stack_tag=get_stack_tag()

        print("######################################")
        print("")
        lifecycle_id = str(input("Enter the lifecycle_id:\n"))
        print("")
        approval_status = str(
            input(
                f"Enter the approval status ({PRODUCTION_APPROVAL_STATUS_APPROVED} or {PRODUCTION_APPROVAL_STATUS_FAILED}):\n"
            )
        )
        if approval_status not in [ PRODUCTION_APPROVAL_STATUS_APPROVED, PRODUCTION_APPROVAL_STATUS_FAILED ]:
            msg = f"approval_status must be {PRODUCTION_APPROVAL_STATUS_APPROVED} or {PRODUCTION_APPROVAL_STATUS_FAILED}"
            logger.error(msg)
            raise ValueError(msg)

        # example_properties = {
        #     "gitlab_pipeline_url": "https://gitlab.com/project-/pipelines/12345"
        # }
        example_properties = None

        ami_approval_request = generate_ami_approval_request(
            operation=operation_type,
            stack_tag=stack_tag,
            approval_status=approval_status,
            properties=example_properties,
            lifecycle_id=lifecycle_id
        )

        print("")
        print("Json Request")
        print(json.dumps(ami_approval_request, indent=2))

        if operation_type == OPERATION_AMI_APPROVAL_CREATE:
            api_endpoint = f"{get_api_endpoint()}/ami-creation/lifecycles/{lifecycle_id}/approve"
        if operation_type == OPERATION_AMI_APPROVAL_PATCH:
            api_endpoint = f"{get_api_endpoint()}/ami-patch/lifecycles/{lifecycle_id}/approve"
        
        print("")
        http_method="POST"
        print(f"{http_method} api_endpoint: {api_endpoint}")

        print("")
        yes_or_no("Do you want to proceed with the API request?")

        response = requests.post(
            url=api_endpoint, 
            json=ami_approval_request
        )

        endpoint_op_type = OPERATION_AMI_CREATE if operation_type == OPERATION_AMI_APPROVAL_CREATE else OPERATION_AMI_PATCH

        print_api_response(response, CLI_MODE_INTERACTIVE, endpoint_op_type)

    except Exception as e:
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        logger.error(f"Error in API invocation: {http_method} api_endpoint: {api_endpoint}")
        print(str(e))


def process_patch_mark_for_production_request(mode: str) -> None:

    try:

        stack_tag=get_stack_tag()

        print("######################################")
        print("")
        lifecycle_id = str(input("Enter the lifecycle_id:\n"))
        print("")
        approval_status = str(
            input(
                f"Enter the approval status ({PRODUCTION_APPROVAL_STATUS_APPROVED} or {PRODUCTION_APPROVAL_STATUS_FAILED}):\n"
            )
        )
        if approval_status not in [ PRODUCTION_APPROVAL_STATUS_APPROVED, PRODUCTION_APPROVAL_STATUS_FAILED ]:
            msg = f"approval_status must be {PRODUCTION_APPROVAL_STATUS_APPROVED} or {PRODUCTION_APPROVAL_STATUS_FAILED}"
            logger.error(msg)
            raise ValueError(msg)

        # example_properties = {
        #     "gitlab_pipeline_url": "https://gitlab.com/project-/pipelines/12345"
        # }
        example_properties = None

        ami_approval_request = generate_ami_approval_request(
            operation=OPERATION_AMI_APPROVAL_PATCH,
            stack_tag=stack_tag,
            approval_status=approval_status,
            properties=example_properties,
            lifecycle_id=lifecycle_id
        )

        print("")
        print("Json Request")
        print(json.dumps(ami_approval_request, indent=2))

        api_endpoint = f"{get_api_endpoint()}/ami-patch/lifecycles/{lifecycle_id}/approve"
        print("")
        http_method="POST"
        print(f"{http_method} api_endpoint: {api_endpoint}")

        print("")
        yes_or_no("Do you want to proceed with the API request?")

        response = requests.post(
            url=api_endpoint, 
            json=ami_approval_request
        )

        print_api_response(response, CLI_MODE_INTERACTIVE, OPERATION_AMI_PATCH)

    except Exception as e:
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        logger.error(f"Error in API invocation: {http_method} api_endpoint: {api_endpoint}")
        print(str(e))


def process_utils_menu(selected_item: str) -> None:
    if selected_item == "Get Status Url by LifecycleId":
        return get_status_url_util(
            mode=CLI_MODE_INTERACTIVE, 
            lifecycle_id=None,
            operation_type=OPERATION_TYPE_CREATE
        )

    if selected_item == "Get Statuses Url":
        return get_statuses_url_util(
            operation_type=OPERATION_TYPE_CREATE
        )

    if selected_item == "Get Timeline Url for AMI Creation":
        return get_timeline_url_util(
            mode=CLI_MODE_INTERACTIVE, 
            lifecycle_id=None,
            operation_type=OPERATION_TYPE_CREATE
        )

    if selected_item == "Get Timeline Url for AMI Patch":
        return get_timeline_url_util(
            mode=CLI_MODE_INTERACTIVE, 
            lifecycle_id=None,
            operation_type=OPERATION_TYPE_PATCH
        )

    if selected_item == "Simulate QA Certification Response":
        return process_qa_certification_request(
            mode=CLI_MODE_INTERACTIVE
        )

    if selected_item == "Simulate AMI Approval AMI Creation":
        return process_mark_for_production_request(
            mode=CLI_MODE_INTERACTIVE,
            operation_type=OPERATION_AMI_APPROVAL_CREATE
        )

    if selected_item == "Simulate AMI Approval AMI Patch":
        return process_mark_for_production_request(
            mode=CLI_MODE_INTERACTIVE,
            operation_type=OPERATION_AMI_APPROVAL_PATCH
        )


def display_menus() -> None:
    main_menu_title = "  AMI Management API Menu\n"
    main_menu_items = ["Create AMI", "Update AMI", "Patch approved AMI", "Continue AMI Patching", "Utils", "Quit"]
    main_menu_cursor = "> "
    main_menu_cursor_style = ("fg_red", "bold")
    main_menu_style = ("bg_yellow", "fg_black")
    main_menu_exit = False

    main_menu = TerminalMenu(
        menu_entries=main_menu_items,
        title=main_menu_title,
        menu_cursor=main_menu_cursor,
        menu_cursor_style=main_menu_cursor_style,
        menu_highlight_style=main_menu_style,
        cycle_cursor=True,
        clear_screen=True,
    )

    create_ami_menu = TerminalMenu(
        title="  Create AMI Menu\n",
        menu_entries=["AMI Build only", "Smoke Tests", "Vulnerability Scans", "QA Certification", "Previous Menu"],
        multi_select=True,
        show_multi_select_hint=True,
        clear_screen=False
    )

    create_update_ami_menu = TerminalMenu(
        title="  Update a non-production AMI Menu\n",
        menu_entries=["Smoke Tests", "Vulnerability Scans", "QA Certification", "Previous Menu"],
        multi_select=True,
        show_multi_select_hint=True,
        clear_screen=False
    )

    patch_ami_menu = TerminalMenu(
        title="  Patch AMI Menu\n",
        menu_entries=["AMI Patch only", "Smoke Tests", "Vulnerability Scans", "Previous Menu"],
        multi_select=True,
        show_multi_select_hint=True,
        clear_screen=False
    )

    patch_update_ami_menu = TerminalMenu(
        title="  Continue patch operation AMI Menu\n",
        menu_entries=["Smoke Tests", "Vulnerability Scans", "Previous Menu"],
        multi_select=True,
        show_multi_select_hint=True,
        clear_screen=False
    )

    utils_menu_entries=[
        "Get Status Url by LifecycleId",
        "Get Statuses Url",
        "Get Timeline Url for AMI Creation", 
        "Get Timeline Url for AMI Patch", 
        "Simulate QA Certification Response", 
        "Simulate AMI Approval AMI Creation", 
        "Simulate AMI Approval AMI Patch",
        "Previous Menu"
    ]
    utils_menu = TerminalMenu(
        title="  API Utils Menu\n",
        menu_entries=utils_menu_entries,
        multi_select=False,
        show_multi_select_hint=False,
        clear_screen=False
    )


    while not main_menu_exit:
        main_sel = main_menu.show()

        if main_sel == 0:
            create_ami_menu_back = False
            while not create_ami_menu_back:
                create_amimenu_entry_indices = create_ami_menu.show()
                selected_items = create_ami_menu.chosen_menu_entries
                if "Previous Menu" in selected_items:
                    create_ami_menu_back = True
                    main_sel = main_menu.show()
                else:
                    process_ami_create_request(
                        operation=OPERATION_AMI_CREATE,
                        selected_items=create_ami_menu.chosen_menu_entries
                    )
                    create_ami_menu_back = True
                    main_menu_exit = True
        if main_sel == 1:
            create_update_ami_menu_back = False
            while not create_update_ami_menu_back:
                create_update_amimenu_entry_indices = create_update_ami_menu.show()
                selected_items = create_update_ami_menu.chosen_menu_entries
                if "Previous Menu" in selected_items:
                    create_update_ami_menu_back = True
                    main_sel = main_menu.show()
                else:
                    process_ami_create_request(
                        operation=OPERATION_AMI_CREATE_UPDATE,
                        selected_items=create_update_ami_menu.chosen_menu_entries
                    )
                    create_update_ami_menu_back = True
                    main_menu_exit = True
        if main_sel == 2:
            patch_ami_menu_back = False
            while not patch_ami_menu_back:
                patch_amimenu_entry_indices = patch_ami_menu.show()
                selected_items = patch_ami_menu.chosen_menu_entries
                if "Previous Menu" in selected_items:
                    patch_ami_menu_back = True
                    main_sel = main_menu.show()
                else:
                    process_ami_patch_request(
                        operation=OPERATION_AMI_PATCH,
                        selected_items=patch_ami_menu.chosen_menu_entries
                    )
                    patch_ami_menu_back = True
                    main_menu_exit = True
        if main_sel == 3:
            patch_update_ami_menu_back = False
            while not patch_update_ami_menu_back:
                patch_update_amimenu_entry_indices = patch_update_ami_menu.show()
                selected_items = patch_update_ami_menu.chosen_menu_entries
                if "Previous Menu" in selected_items:
                    patch_update_ami_menu_back = True
                    main_sel = main_menu.show()
                else:
                    process_ami_patch_request(
                        operation=OPERATION_AMI_PATCH_UPDATE,
                        selected_items=patch_update_ami_menu.chosen_menu_entries
                    )
                    patch_update_ami_menu_back = True
                    main_menu_exit = True
        if main_sel == 4:
            utils_menu_back = False
            while not utils_menu_back:
                utils_menu_entry_index = utils_menu.show()
                selected_item = utils_menu_entries[utils_menu_entry_index]
                if "Previous Menu" in selected_item:
                    utils_menu_back = True
                    main_sel = main_menu.show()
                else:
                    process_utils_menu(selected_item)
                    utils_menu_back = True
                    main_menu_exit = True
        if main_sel == 5:
            print("Thank you and goodbye.")
            sys.exit(0)


##########################################################
# </END> Interactive mode (UI) specific functions
##########################################################


##########################################################
# <START> Batch mode specific functions
##########################################################

def process_batch_ami_create_request(
    operation: str,
    stack_tag: str,
    owner: str,
    notifications: list,
    smoke_tests: bool,
    vulnerability_scans: bool,
    qa_certification: bool,
    properties: dict,
    lifecycle_id: str,
    product_ver: str,
    product_name: str
) -> None:

    ami_request = generate_ami_create_request(
        operation=operation,
        stack_tag=stack_tag,
        owner=owner,
        properties=properties,
        notifications=notifications,
        smoke_tests=smoke_tests,
        vulnerability_scans=vulnerability_scans,
        qa_certification=qa_certification,
        lifecycle_id=lifecycle_id,
        product_ver=product_ver,
        product_name=product_name,
        commit_ref=get_git_commit_ref() if operation == OPERATION_AMI_CREATE else None
    )

    logger.debug("Json Request")
    logger.debug(json.dumps(ami_request, indent=2))

    api_endpoint = f"{get_api_endpoint()}/ami-creation/lifecycles"
    http_method="POST" if operation == OPERATION_AMI_CREATE else "PUT"
    logger.debug(f"{http_method} api_endpoint: {api_endpoint}")

    try:
        if operation == OPERATION_AMI_CREATE:
            response = requests.post(
                url=api_endpoint, 
                json=ami_request
            )
        elif operation == OPERATION_AMI_CREATE_UPDATE:
            response = requests.put(
                url=api_endpoint, 
                json=ami_request
            )

        print_api_response(response, CLI_MODE_BATCH, OPERATION_AMI_CREATE)
    except Exception as e:
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        logger.error(f"Error in API invocation: {http_method} api_endpoint: {api_endpoint}")
        print(str(e))


def process_batch_ami_patch_request(
    operation: str,
    stack_tag: str,
    owner: str,
    notifications: list,
    smoke_tests: bool,
    vulnerability_scans: bool,
    properties: dict,
    lifecycle_id: str,
    patch_component_url: str,
    patch_change_description: str,
    semver_bump_type: str
) -> None:

    ami_request = generate_ami_patch_request(
        operation=operation,
        stack_tag=stack_tag,
        owner=owner,
        properties=properties,
        notifications=notifications,
        smoke_tests=smoke_tests,
        vulnerability_scans=vulnerability_scans,
        lifecycle_id=lifecycle_id,
        patch_component_url=patch_component_url,
        patch_change_description=patch_change_description,
        semver_bump_type=semver_bump_type,
        commit_ref=get_git_commit_ref() if operation == OPERATION_AMI_PATCH else None
    )

    logger.debug("Json Request")
    logger.debug(json.dumps(ami_request, indent=2))

    api_endpoint = f"{get_api_endpoint()}/ami-patch/lifecycles"
    http_method="POST" if operation == OPERATION_AMI_PATCH else "PUT"
    logger.debug(f"{http_method} api_endpoint: {api_endpoint}")

    try:
        if operation == OPERATION_AMI_PATCH:
            response = requests.post(
                url=api_endpoint, 
                json=ami_request
            )
        elif operation == OPERATION_AMI_PATCH_UPDATE:
            response = requests.put(
                url=api_endpoint, 
                json=ami_request
            )

        print_api_response(response, CLI_MODE_BATCH, OPERATION_AMI_PATCH)
    except Exception as e:
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        logger.error(f"Error in API invocation: {http_method} api_endpoint: {api_endpoint}")
        print(str(e))


def process_batch_qa_certification_request(
        stack_tag: str,
        certification_status: str,
        properties: dict,
        lifecycle_id: str
    ) -> None:

    try:

        qa_certify_request = generate_ami_qa_certification_request(
            operation=OPERATION_AMI_QA_CERTIFICATION,
            stack_tag=stack_tag,
            certification_status=certification_status,
            properties=None if properties is None else properties,
            lifecycle_id=lifecycle_id
        )

        logger.debug("Json Request")
        logger.debug(json.dumps(qa_certify_request, indent=2))

        api_endpoint = f"{get_api_endpoint()}/ami-creation/lifecycles/{lifecycle_id}/certify"
        http_method="POST"
        logger.debug(f"{http_method} api_endpoint: {api_endpoint}")

        response = requests.post(
            url=api_endpoint, 
            json=qa_certify_request
        )

        print_api_response(response, CLI_MODE_BATCH, OPERATION_AMI_CREATE)

    except Exception as e:
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        logger.error(f"Error in API invocation: {http_method} api_endpoint: {api_endpoint}")
        print(str(e))


def process_batch_ami_approval_request(
        stack_tag: str,
        approval_status: str,
        properties: dict,
        lifecycle_id: str,
        operation_type: str
    ) -> None:

    try:

        ami_approval_request = generate_ami_approval_request(
            operation=operation_type,
            stack_tag=stack_tag,
            approval_status=approval_status,
            properties=None if properties is None else properties,
            lifecycle_id=lifecycle_id
        )

        logger.debug("Json Request")
        logger.debug(json.dumps(ami_approval_request, indent=2))

        if operation_type == OPERATION_AMI_APPROVAL_CREATE:
            api_endpoint = f"{get_api_endpoint()}/ami-creation/lifecycles/{lifecycle_id}/approve"
        if operation_type == OPERATION_AMI_APPROVAL_PATCH:
            api_endpoint = f"{get_api_endpoint()}/ami-patch/lifecycles/{lifecycle_id}/approve"
        
        
        http_method="POST"
        logger.debug(f"{http_method} api_endpoint: {api_endpoint}")

        response = requests.post(
            url=api_endpoint, 
            json=ami_approval_request
        )

        endpoint_op_type = OPERATION_AMI_CREATE if operation_type == OPERATION_AMI_APPROVAL_CREATE else OPERATION_AMI_PATCH

        print_api_response(response, CLI_MODE_BATCH, endpoint_op_type)

    except Exception as e:
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        logger.error(f"Error in API invocation: {http_method} api_endpoint: {api_endpoint}")
        print(str(e))

##########################################################
# </END> Batch mode specific functions
##########################################################


##########################################################
# <START> MAIN - Argument parsers
##########################################################

def main(args) -> None:
    if args.mode == CLI_MODE_INTERACTIVE:
        display_menus()
    else:
        # we are in BATCH mode

        # check the operation
        if not args.operation:
            logger.error(f"The --operations argument is required for {CLI_MODE_BATCH} mode.")
            sys.exit(99)
        if args.operation:

            # validate lifecycle id
            if args.operation != OPERATION_AMI_CREATE and args.operation != OPERATION_AMI_GET_STATUSES:
                if not args.lifecycleId:
                    logger.error(f"The lifecycleId argument is required for {args.operation} operation.")
                    sys.exit(99)  

            ####################################################
            # GET OPERATIONS
            ####################################################
            if args.operation == OPERATION_AMI_GET_STATUS_BY_LIFECYCLE_ID:
                if args.stackTag:
                    get_status_url_util(
                        mode=CLI_MODE_BATCH, 
                        lifecycle_id=args.lifecycleId,
                        operation_type=OPERATION_TYPE_CREATE
                    )
                    sys.exit(0)
                else:
                    logger.error(f"The stackTag argument is required for {args.operation} operation.")
                    sys.exit(99)

            if args.operation == OPERATION_AMI_GET_STATUSES:
                get_statuses_url_util( 
                    operation_type=OPERATION_TYPE_CREATE
                )
                sys.exit(0)

            if args.operation == OPERATION_AMI_TIMELINE_CREATE:
                get_timeline_url_util(
                    mode=CLI_MODE_BATCH, 
                    lifecycle_id=args.lifecycleId,
                    operation_type=OPERATION_TYPE_CREATE
                )
                sys.exit(0)

            if args.operation == OPERATION_AMI_TIMELINE_PATCH:
                get_timeline_url_util(
                    mode=CLI_MODE_BATCH, 
                    lifecycle_id=args.lifecycleId,
                    operation_type=OPERATION_TYPE_PATCH
                )
                sys.exit(0)  

            ####################################################
            # POST/PUT OPERATIONS
            ####################################################

            ### AMI CREATE or AMI CREATE UPDATE
            if args.operation == OPERATION_AMI_CREATE or args.operation == OPERATION_AMI_CREATE_UPDATE:
                # proceed with the CREATE/UPDATE/PATCH operations
                required_args = {
                    "events": args.events,
                    "owner": args.owner,
                    "stacktag": args.stackTag,
                    "notifications":args.notifications
                }

                # add AMI CREATE specific args
                if args.operation == OPERATION_AMI_CREATE:
                    required_args['productname'] = args.productName
                    required_args['productver'] = args.productVer

                # add AMI CREATE UPDATE specific args
                if args.operation == OPERATION_AMI_CREATE_UPDATE:
                    required_args['lifecycleid'] = args.lifecycleId

                # validate required args
                for required_arg in required_args.items():
                    arg_name = required_arg[0]
                    arg_value = required_arg[1]
                    if not arg_value:
                        logger.error(f"The {arg_name} argument is required for {args.operation} operation in {CLI_MODE_BATCH} mode.")
                        sys.exit(99)

                notifications = []
                for notification in args.notifications:
                    notification_obj = notification.split(ARG_SEPERATOR)
                    notifications.append(
                        { 
                            'method': notification_obj[0],
                            'target': notification_obj[1]
                        }
                    )

                if not args.properties:
                    props = None
                else:
                    props = {}
                    for prop in args.properties:
                        prop_obj = prop.split(ARG_SEPERATOR)
                        props[prop_obj[0]]= prop_obj[1]

                process_batch_ami_create_request(
                    operation=args.operation,
                    stack_tag=args.stackTag,
                    owner=args.owner,
                    notifications=notifications,
                    smoke_tests=True if CLI_EVENT_SMOKE_TESTS in args.events else False,
                    vulnerability_scans=True if CLI_EVENT_VULNERABILITY_SCANS in args.events else False,
                    qa_certification=True if CLI_EVENT_QA_CERTIFY_REQUEST in args.events else False,
                    properties=props,
                    lifecycle_id=args.lifecycleId if args.lifecycleId else None,
                    product_name=args.productName if args.productName else None,
                    product_ver=args.productVer if args.productVer else None
                )


            ### AMI CREATE QA CERTIFICATION
            if args.operation == OPERATION_AMI_QA_CERTIFICATION:

                required_args = {
                    "lifecycleid": args.lifecycleId,
                    "certification_status": args.certificationStatus,
                    "stacktag": args.stackTag
                }

                # validate required args
                for required_arg in required_args.items():
                    arg_name = required_arg[0]
                    arg_value = required_arg[1]
                    if not arg_value:
                        logger.error(f"The {arg_name} argument is required for {OPERATION_AMI_QA_CERTIFICATION} in {CLI_MODE_BATCH} mode.")
                        sys.exit(99)


                if not args.properties:
                    props = None
                else:
                    props = {}
                    for prop in args.properties:
                        prop_obj = prop.split(ARG_SEPERATOR)
                        props[prop_obj[0]]= prop_obj[1]


                process_batch_qa_certification_request(
                    stack_tag=args.stackTag,
                    certification_status=args.certificationStatus,
                    properties=props,
                    lifecycle_id=args.lifecycleId if args.lifecycleId else None
                )

            ### AMI CREATE AMI APPROVAL
            if args.operation == OPERATION_AMI_APPROVAL_CREATE:

                required_args = {
                    "lifecycleid": args.lifecycleId,
                    "approval_status": args.approvalStatusAmiCreation,
                    "stacktag": args.stackTag
                }

                # validate required args
                for required_arg in required_args.items():
                    arg_name = required_arg[0]
                    arg_value = required_arg[1]
                    if not arg_value:
                        logger.error(f"The {arg_name} argument is required for {OPERATION_AMI_QA_CERTIFICATION} in {CLI_MODE_BATCH} mode.")
                        sys.exit(99)


                if not args.properties:
                    props = None
                else:
                    props = {}
                    for prop in args.properties:
                        prop_obj = prop.split(ARG_SEPERATOR)
                        props[prop_obj[0]]= prop_obj[1]


                process_batch_ami_approval_request(
                    stack_tag=args.stackTag,
                    approval_status=args.approvalStatusAmiCreation,
                    properties=props,
                    lifecycle_id=args.lifecycleId if args.lifecycleId else None,
                    operation_type=OPERATION_AMI_APPROVAL_CREATE
                )


            ### AMI PATCH or AMI PATCH UPDATE
            if args.operation == OPERATION_AMI_PATCH or args.operation == OPERATION_AMI_PATCH_UPDATE:
                # proceed with the CREATE/UPDATE/PATCH operations
                required_args = {
                    "events": args.events,
                    "owner": args.owner,
                    "stacktag": args.stackTag,
                    "notifications": args.notifications
                }

                if args.operation == OPERATION_AMI_PATCH:
                    required_args["patchComponent"] = args.patchComponent
                    required_args["patchChangeDescription"] = args.patchChangeDescription
                    required_args["semverBumpType"] = args.semverBumpType

                # validate required args
                for required_arg in required_args.items():
                    arg_name = required_arg[0]
                    arg_value = required_arg[1]
                    if not arg_value:
                        logger.error(f"The {arg_name} argument is required for {args.operation} operation in {CLI_MODE_BATCH} mode.")
                        sys.exit(99)

                notifications = []
                for notification in args.notifications:
                    notification_obj = notification.split(ARG_SEPERATOR)
                    notifications.append(
                        { 
                            'method': notification_obj[0],
                            'target': notification_obj[1]
                        }
                    )

                if not args.properties:
                    props = None
                else:
                    props = {}
                    for prop in args.properties:
                        prop_obj = prop.split(ARG_SEPERATOR)
                        props[prop_obj[0]]= prop_obj[1]

                process_batch_ami_patch_request(
                    operation=args.operation,
                    stack_tag=args.stackTag,
                    owner=args.owner,
                    notifications=notifications,
                    smoke_tests=True if CLI_EVENT_SMOKE_TESTS in args.events else False,
                    vulnerability_scans=True if CLI_EVENT_VULNERABILITY_SCANS in args.events else False,
                    properties=props,
                    lifecycle_id=args.lifecycleId if args.lifecycleId else None,
                    patch_component_url=None if not args.patchComponent else args.patchComponent,
                    patch_change_description=None if not args.patchChangeDescription else args.patchChangeDescription,
                    semver_bump_type=None if not args.semverBumpType else args.semverBumpType
                )


            ### AMI PATCH AMI APPROVAL
            if args.operation == OPERATION_AMI_APPROVAL_PATCH:

                required_args = {
                    "lifecycleid": args.lifecycleId,
                    "approval_status": args.approvalStatusAmiPatch,
                    "stacktag": args.stackTag
                }

                # validate required args
                for required_arg in required_args.items():
                    arg_name = required_arg[0]
                    arg_value = required_arg[1]
                    if not arg_value:
                        logger.error(f"The {arg_name} argument is required for {OPERATION_AMI_QA_CERTIFICATION} in {CLI_MODE_BATCH} mode.")
                        sys.exit(99)


                if not args.properties:
                    props = None
                else:
                    props = {}
                    for prop in args.properties:
                        prop_obj = prop.split(ARG_SEPERATOR)
                        props[prop_obj[0]]= prop_obj[1]


                process_batch_ami_approval_request(
                    stack_tag=args.stackTag,
                    approval_status=args.approvalStatusAmiPatch,
                    properties=props,
                    lifecycle_id=args.lifecycleId if args.lifecycleId else None,
                    operation_type=OPERATION_AMI_APPROVAL_PATCH
                )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='python3 api-cli.py')

    # select mode
    parser.add_argument(
        '--mode',  
        help=f'{CLI_MODE_INTERACTIVE} for Interactive Menu, {CLI_MODE_BATCH} for scripting.',
        type=str,
        choices={ CLI_MODE_INTERACTIVE, CLI_MODE_BATCH },
        required=True
    )

    # select AMI operation
    parser.add_argument(
        '--operation',  
        help=f'Choose the AMI operation. Required for {CLI_MODE_BATCH} mode.',
        type=str,
        choices={ 
            OPERATION_AMI_CREATE, 
            OPERATION_AMI_CREATE_UPDATE, 
            OPERATION_AMI_PATCH, 
            OPERATION_AMI_PATCH_UPDATE, 
            OPERATION_AMI_GET_STATUS_BY_LIFECYCLE_ID,
            OPERATION_AMI_GET_STATUSES,
            OPERATION_AMI_TIMELINE_CREATE,
            OPERATION_AMI_TIMELINE_PATCH,
            OPERATION_AMI_APPROVAL_CREATE,
            OPERATION_AMI_APPROVAL_PATCH,
            OPERATION_AMI_QA_CERTIFICATION
        }
    )

    # select AMI events
    parser.add_argument(
        '--events', 
        action='append',
        help='List the AMI lifecycle events to execute.', 
        type=str,
        choices={ 
            CLI_EVENT_BUILD_ONLY,
            CLI_EVENT_PATCH_ONLY, 
            CLI_EVENT_SMOKE_TESTS, 
            CLI_EVENT_VULNERABILITY_SCANS,
            CLI_EVENT_QA_CERTIFY_REQUEST
        }
    )

    # ownerargs.approval_status
    parser.add_argument(
        '--owner', 
        help='The name of the user or process initiating the lifecycle request.', 
        type=str
    )

    # stack tag
    parser.add_argument(
        '--stackTag', 
        help='The stack tag of the feature branch.', 
        type=str
    )

    # lifecycle id
    lifecycle_id_required_for = [
        OPERATION_AMI_CREATE_UPDATE,
        OPERATION_AMI_PATCH,
        OPERATION_AMI_PATCH_UPDATE,
        OPERATION_AMI_GET_STATUS_BY_LIFECYCLE_ID,
        OPERATION_AMI_TIMELINE_CREATE,
        OPERATION_AMI_TIMELINE_PATCH
    ]
    parser.add_argument(
        '--lifecycleId', 
        help=f"Lifecycle id. Required for {','.join(lifecycle_id_required_for)} operations." ,
        type=str
    )

    # product_name
    product_name_msg = (
        'The product name to be associated with the lifecycle request. ' +
        f'Required for {OPERATION_AMI_CREATE} operation.'
    )
    parser.add_argument(
        '--productName',  
        help=product_name_msg, 
        type=str
    )

    # product_ver
    product_ver_msg = (
        'The product version to be associated with the lifecycle request. ' +
        f'Required for {OPERATION_AMI_CREATE} operation.'
    )
    parser.add_argument(
        '--productVer',  
        help=product_ver_msg, 
        type=str
    )

    # notifications
    notification_msg = (
        'Targets for push notifications. ' +
        f'Format is METHOD{ARG_SEPERATOR}ENDPOINT. ' +
        f'E.g. EMAIL{ARG_SEPERATOR}user at domain.com'
    )
    parser.add_argument(
        '--notifications', 
        action='append', 
        help=notification_msg, 
        type=str
    )

    # properties
    properties_msg = (
        'Arbitrary properties that will be persisted with the request. ' +
        f'Format is Key{ARG_SEPERATOR}Value. ' +
        f'E.g. CI_COMMIT_ID{ARG_SEPERATOR}443ceed5bfe'
    )
    parser.add_argument(
        '--properties', 
        action='append', 
        help=properties_msg, 
        type=str
    )

    # certification status
    parser.add_argument(
        '--certificationStatus', 
        help='QA Certfication status.', 
        type=str,
        choices={ 
            QA_CERTIFICATION_STATUS_CERTIFIED, 
            QA_CERTIFICATION_STATUS_FAILED
        }
    )

    # mark for production status
    parser.add_argument(
        '--approvalStatusAmiCreation', 
        help='AMI Creation Mark for Production Approval status.', 
        type=str,
        choices={ 
            PRODUCTION_APPROVAL_STATUS_APPROVED, 
            PRODUCTION_APPROVAL_STATUS_FAILED
        }
    )

    parser.add_argument(
        '--approvalStatusAmiPatch', 
        help='AMI Patch Mark for Production Approval status.', 
        type=str,
        choices={ 
            PRODUCTION_APPROVAL_STATUS_APPROVED, 
            PRODUCTION_APPROVAL_STATUS_FAILED
        }
    )

    # patch component
    parser.add_argument(
        '--patchComponent', 
        help=f'Absolute path to the patch component YAML file. Required for {OPERATION_AMI_PATCH} operation.', 
        type=str
    )

    # patch component
    parser.add_argument(
        '--patchChangeDescription', 
        help=f'Text describing the patch change. Required for {OPERATION_AMI_PATCH} operation.', 
        type=str
    )

    # semver_bump_type
    semver_bump_type_msg = (
        'The Semantic Version bump type associated with the lifecycle AMI Patch request. ' +
        f'Required for {OPERATION_AMI_PATCH} operation.'
    )
    parser.add_argument(
        '--semverBumpType',  
        help=semver_bump_type_msg,
        choices={ 
            SEMVER_BUMP_TYPE_MINOR,
            SEMVER_BUMP_TYPE_PATCH
        },
        type=str
    )

    args = parser.parse_args()

    main(args)
