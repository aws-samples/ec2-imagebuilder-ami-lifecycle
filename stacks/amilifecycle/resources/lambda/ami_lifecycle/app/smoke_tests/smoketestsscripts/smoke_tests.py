#!/usr/bin/env python

"""
    smoke_tests.py:
    Sample python script that demonstrates how smoke tests
    can be executed on an EC2 instance to validate an AMI.
"""

import datetime
import json
import logging
import os
import time
import traceback

import boto3

# grab envars
LOG_GROUP_NAME=os.environ['LOG_GROUP_NAME']
LIFECYCLE_ID=os.environ['LIFECYCLE_ID']
AMI_ID=os.environ['AMI_ID']
AMI_NAME=os.environ['AMI_NAME']
AMI_OWNER=os.environ['AMI_OWNER']
AMI_REGION=os.environ['AMI_REGION']
SQS_QUEUE_URL=os.environ['SQS_QUEUE_URL']
TASK_TOKEN=os.environ['TASK_TOKEN']
API_KEY=os.environ['API_KEY']
TEST_DIR=os.environ['TEST_DIR']
VPC_ID=os.environ['VPC_ID']
SUBNET_ID=os.environ['SUBNET_ID']
SECURITY_GROUP_ID=os.environ['SECURITY_GROUP_ID']
EC2_INSTANCE_PROFILE_ARN=os.environ['EC2_INSTANCE_PROFILE_ARN']
INSTANCE_ID=os.environ['INSTANCE_ID']
STACK_TAG=os.environ['STACK_TAG']
OPERATION_TYPE=os.environ['OPERATION_TYPE']

# boto 3
sqs_client = boto3.client('sqs', region_name=AMI_REGION)
stepfunctions_client = boto3.client('stepfunctions', region_name=AMI_REGION)

# configure logging
logFormatter = logging.Formatter("%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s")
logger = logging.getLogger()

fileHandler = logging.FileHandler("{0}/{1}.log".format("/smoketests", "smoketests"))
fileHandler.setFormatter(logFormatter)
logger.addHandler(fileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
logger.addHandler(consoleHandler)

logger.setLevel(logging.DEBUG)

logger.debug("ENVIRONMENT VARIABLES")
logger.debug( '\n'.join([f'{k}: {v}' for k, v in sorted(os.environ.items())]) )


def notify_success():
    logger.info("Notifying the state machine that SMOKE testing has completed successfully.")
    receiver_output = {}
    receiver_output['receiver_status'] = "COMPLETED"
    receiver_output['smoke_test_ec2_instance_id'] = INSTANCE_ID
    receiver_output['operation_type'] = OPERATION_TYPE
    receiver_output['lifecycle_id'] = LIFECYCLE_ID
    receiver_output['stack_tag'] = STACK_TAG

    stepfunctions_client.send_task_success(
        taskToken=TASK_TOKEN,
        output=json.dumps(receiver_output)
    )

def __send_sqs_message(error_message, stack_trace):
    logger.info("Sending error message to SQS.")
    message_body = {
        "lifecycle_id": LIFECYCLE_ID,
        "api_key": API_KEY,
        "status": "ERROR",
        "status_date": datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
        "error_message": error_message,
        "stack_trace": stack_trace
    }

    response = sqs_client.send_message(
        QueueUrl=SQS_QUEUE_URL,
        MessageBody=json.dumps(message_body, separators=(',', ':'))
    )

def notify_failure(error_message, stack_trace):
    logger.info("Notifying state machine of failure.")
    logger.error(error_message)
    logger.error(stack_trace)

    stepfunctions_client.send_task_failure(
        taskToken=TASK_TOKEN,
        cause=str(error_message)
    )

    __send_sqs_message(error_message, stack_trace)



##############################################
# SMOKE TESTS to be added to method below
##############################################
def execute_smoke_tests():

    TEST_RESULT = True

    try:
        for i in range(1,30):
            logger.info(f"Executing test {i}.")
            time.sleep(1)

        if TEST_RESULT:
            notify_success()
        else:
            notify_failure(
                error_message=f"Smoke tests have failed for ami {AMI_ID}.",
                stack_trace=f"FAILED_SMOKE_TESTS_FOR_AMI_{AMI_ID}"
            )
    except Exception as e:
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        stack_trace = traceback.format_exc()

        logger.error(f'Error executing smoke tests for ami {AMI_ID}: {str(e)}')

        notify_failure(
            error_message=str(e),
            stack_trace=stack_trace
        )


# execute smoke tests
logger.info(f"Executing smoke tests for ami: {AMI_ID}")
execute_smoke_tests()
