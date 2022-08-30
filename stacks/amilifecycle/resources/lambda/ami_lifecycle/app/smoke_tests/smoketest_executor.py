#!/usr/bin/env python

"""
    smoketest_executor.py:
    Lambda function that launches an EC2 instance and executes
    smoke tests on the launched instance as part of the
    AMI lifecycle SMOKE_TESTS State Machine.
"""

import datetime
import json
import logging
import os
import traceback

import boto3

# constants
OPERATOR = "SMOKE_TESTS_TEST_EXECUTOR"

# env vars
STACK_TAG=os.environ['STACK_TAG']
TEST_CASE_ASSETS=os.environ['TEST_CASE_ASSETS']
EBS_VOLUME_SIZE=int(os.environ['EBS_VOLUME_SIZE'])
EC2_INSTANCE_TYPE=os.environ['EC2_INSTANCE_TYPE']
SQS_QUEUE_URL=os.environ['SQS_QUEUE_URL']
LOG_GROUP_NAME=os.environ['LOG_GROUP_NAME']
EC2_INSTANCE_PROFILE_ARN=os.environ['EC2_INSTANCE_PROFILE_ARN']
VPC_ID=os.environ['VPC_ID']
SUBNET_ID=os.environ['SUBNET_ID']
SECURITY_GROUP_ID=os.environ['SECURITY_GROUP_ID']
SMOKE_TESTS_TIMEOUT=os.environ['SMOKE_TESTS_TIMEOUT']

# boto 3
sqs_client = boto3.client('sqs')
stepfunctions_client = boto3.client('stepfunctions')
ec2_client = boto3.client('ec2')

# set logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


def replace_placeholders(template_file: str, substitutions: dict) -> str:
    import re

    def from_dict(dct):
        def lookup(match):
            key = match.group(1)
            return dct.get(key, f'<{key} not found>')
        return lookup

    with open (template_file, "r") as template_file:
        template_data = template_file.read()

    # perform the subsitutions, looking for placeholders @@PLACEHOLDER@@
    api_template = re.sub('@@(.*?)@@', from_dict(substitutions), template_data)

    return api_template


def execute_smoke_tests(
        ami_id, 
        user_data_script,
        lifecycle_id
    ) -> None:

    logger.info("Launching EC2 instance for smoke testing")
    response = ec2_client.run_instances(
        BlockDeviceMappings=[
            {
                'DeviceName': '/dev/xvda',
                'Ebs': {

                    'DeleteOnTermination': True,
                    'VolumeSize': EBS_VOLUME_SIZE,
                    'VolumeType': 'gp2'
                },
            },
        ],
        IamInstanceProfile={
            'Arn': EC2_INSTANCE_PROFILE_ARN
        },
        ImageId=ami_id,
        InstanceType=EC2_INSTANCE_TYPE,
        MaxCount=1,
        MinCount=1,
        Monitoring={
            'Enabled': False
        },
        SecurityGroupIds=[
            SECURITY_GROUP_ID
        ],
        SubnetId=SUBNET_ID,
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [
                    {
                        'Key': 'Usage',
                        'Value': 'AMI Lifecycle Smoke Test'
                    },
                    {
                        'Key': 'STACK_TAG',
                        'Value': STACK_TAG
                    },
                    {
                        'Key': 'AMI Lifecycle Id',
                        'Value': lifecycle_id
                    },
                    {
                        'Key': 'AMI_LC_EVENT_INSTANCE',
                        'Value': 'TRUE'
                    }
                ]
            }
        ],
        UserData=user_data_script
    )


def lambda_handler(event, context):

    # print the event details
    logger.debug(json.dumps(event, indent=2))

    try:

        if event and event["Records"]:
            logger.info(f"New event consumed consisting of {len(event['Records'])} record(s).")
            for record in event["Records"]:

                logger.debug(json.loads(record['body']))
                
                record_body = json.loads(record['body'])

                json_request = record_body['task_details']['value']

                logger.debug(json.dumps(json_request, indent=2))

                expected_inputs = [ "lifecycle_id", "cfn_stack_name", "ami_id", "ami_name", "ami_region", "ami_owner", "api_key" ]
                for expected_input in expected_inputs:
                    if expected_input not in json_request or json_request[expected_input] == "":
                        raise ValueError(f"A valid {expected_input} must be provided as part of the {OPERATOR} input")
    
                # create a map of values to be replace in the user data script
                user_data_substitutions = {
                    "TEST_CASE_ASSETS": TEST_CASE_ASSETS,
                    "LOG_GROUP_NAME": LOG_GROUP_NAME,
                    "LIFECYCLE_ID": json_request['lifecycle_id'],
                    "AMI_ID": json_request['ami_id'],
                    "AMI_NAME": json_request['ami_name'],
                    "AMI_OWNER": json_request['ami_owner'],
                    "AMI_REGION": json_request['ami_region'],
                    "SQS_QUEUE_URL": SQS_QUEUE_URL,
                    "TASK_TOKEN": record_body['task_token'],
                    "API_KEY": json_request['api_key'],
                    "VPC_ID": VPC_ID,
                    "SUBNET_ID": SUBNET_ID,
                    "SECURITY_GROUP_ID":SECURITY_GROUP_ID,
                    "EC2_INSTANCE_PROFILE_ARN": EC2_INSTANCE_PROFILE_ARN,
                    "STACK_TAG": STACK_TAG,
                    "SMOKE_TESTS_TIMEOUT": SMOKE_TESTS_TIMEOUT,
                    "OPERATION_TYPE": json_request['operation_type']
                }

                user_data_script = replace_placeholders(
                    f"{os.path.dirname(__file__)}/userdata/user_data.sh",
                    user_data_substitutions
                )

                logger.info("Executing smoke tests on EC2 instance")
                execute_smoke_tests(
                    ami_id=json_request['ami_id'],
                    user_data_script=user_data_script,
                    lifecycle_id=json_request['lifecycle_id']
                )

    except Exception as e:
        
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        stack_trace = traceback.format_exc()

        logger.error(f'Error in executing {OPERATOR} operation: {str(e)}')

        stepfunctions_client.send_task_failure(
            taskToken=record_body['task_token'],
            cause=str(e)
        )

        logger.info("Sending error message to SQS.")
        message_body = {
            "lifecycle_id": json_request['lifecycle_id'],
            "api_key": json_request['api_Key'],
            "status": "ERROR",
            "status_date": datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            "error_message": str(e),
            "stack_trace": stack_trace
        }

        response = sqs_client.send_message(
            QueueUrl=SQS_QUEUE_URL,
            MessageBody=json.dumps(message_body, separators=(',', ':'))
        )
