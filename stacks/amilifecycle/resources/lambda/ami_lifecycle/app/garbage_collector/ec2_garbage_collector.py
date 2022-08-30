#!/usr/bin/env python

"""
    ec2_garbage_collector.py:
    Lambda function that executes according to a CloudWatch Events periodic
    schedule. The function checks for any EC2 instances that have been created by the
    AMI Lifecycle State Machines. If these EC2 instances have been running for longer
    than a pre-defined threshold, the EC2 instances will be terminated.
"""

import json
import logging
import os
import traceback
from datetime import datetime

import boto3

# constants
OPERATOR = "AMI_LIFECYCLE_GARBAGE_COLLECTOR"

# Environment variables
# Number of hours that an EC2 instance can run for before being considered a zombie
MAX_INSTANCE_RUNTIME_HOURS = int(os.environ['MAX_INSTANCE_RUNTIME_HOURS'])

# boto 3
ec2_client = boto3.client('ec2')

# set logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


def get_zombied_lifecycle_instances() -> list:
    logger.info("Checking for EC2 instances with the AMI_LC_EVENT_INSTANCE tag")

    paginator = ec2_client.get_paginator('describe_instances')

    response_iterator = paginator.paginate(
        Filters=[
            {
                'Name': 'tag:AMI_LC_EVENT_INSTANCE',
                'Values': [
                    'TRUE',
                ]
            },
        ]
    ).build_full_result()

    instance_ids = []
    
    compare_time = datetime.now().astimezone()

    for reservation in response_iterator.get('Reservations', []):
        for instance in reservation.get('Instances', []):
            launch_time = instance.get('LaunchTime', None)
            if launch_time:
                td = compare_time - launch_time.astimezone()
                days, hours, minutes = td.days, td.seconds // 3600, td.seconds // 60 % 60
                logger.debug(f"Instance Id: {instance.get('InstanceId')}  uptime is days, hours, minutes == {days}, {hours}, {minutes}")
                if hours > MAX_INSTANCE_RUNTIME_HOURS:
                    logger.debug(
                        f"Instance {instance.get('InstanceId')} has been running for "
                        f"{hours} hours and {minutes} minutes which is longer than the max runtime of "
                        f"{MAX_INSTANCE_RUNTIME_HOURS} hours. This instance will be added "
                        "as a candidate for termination."
                    )
                    instance_ids.append(instance.get('InstanceId'))

    logger.debug("Instance ids to be terminated")
    logger.debug(instance_ids)

    return instance_ids


def terminate_ec2_instances(instance_ids: list) -> None:
    
    logger.info("Terminating the following AMI Lifecycle Event instances.")
    logger.info("These instances execeded the max run time and are no longer required.")
    logger.info(','.join(instance_ids))

    response = ec2_client.terminate_instances(
        InstanceIds=instance_ids
    )


def lambda_handler(event, context):

    # print the event details
    logger.debug(json.dumps(event, indent=2))

    try:

        logger.info("Garbage Collector invocation")

        instance_ids = get_zombied_lifecycle_instances()

        if len(instance_ids) == 0:
            return {
                'statusCode': 200,
                'body': { "message": "No matching EC2 instances require termination"},
                'headers': {'Content-Type': 'application/json'}
            }

        terminate_ec2_instances(instance_ids)
        
        return {
            'statusCode': 200,
            'body': { "message": f"Instances terminated: {','.join(instance_ids)}"},
            'headers': {'Content-Type': 'application/json'}
        }
        
    except Exception as e:
        
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)

        logger.error(f'Error in executing {OPERATOR} operation: {str(e)}')

        return {
            'statusCode': 500,
            'body': { 'error': str(e) },
            'headers': {'Content-Type': 'application/json'}
        }
