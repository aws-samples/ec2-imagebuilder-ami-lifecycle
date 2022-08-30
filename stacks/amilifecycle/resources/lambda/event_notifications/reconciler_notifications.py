#!/usr/bin/env python

"""
    reconciler_notifications.py:
    Lambda that subscribes to an SNS topic. The SNS topic receives notifications 
    related to AMI tag reconciliation events. The reconciler process ensures that the AMI Lifecycle
    generated AMI tags match the AMI metadata stored in DynamoDB. 
"""

import datetime
import json
import logging
import os
import time
import traceback
import uuid

import boto3

# set logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# boto3
client = boto3.client('logs')

# environment variables
LOG_GROUP_NAME = os.environ['LOG_GROUP_NAME']


def lambda_handler(event, context):

    # print the event details
    logger.debug(json.dumps(event, indent=2))

    try:

        if event and event["Records"]:
            logger.info(f"New event consumed consisting of {len(event['Records'])} record(s).")
            for record in event["Records"]:

                if 'Sns' in record:
                    logger.debug(json.dumps(record['Sns'], indent=2))

                    sns_record = record['Sns']
                    
                    log_stream_name = f"{datetime.datetime.now().strftime('%Y/%m/%d/')}{uuid.uuid4()}"

                    logger.debug(f"log_stream_name == {log_stream_name}")
                
                    # check if the log stream exists
                    describe_response = client.describe_log_streams(
                        logGroupName=LOG_GROUP_NAME,
                        logStreamNamePrefix=log_stream_name,
                        limit=1
                    )
                    
                    logger.debug(json.dumps(describe_response, indent=2))

                    create_log_stream = True
                    if 'logStreams' in describe_response:
                        if len(describe_response['logStreams']) > 0:
                            create_log_stream = False
                            if 'uploadSequenceToken' in describe_response['logStreams'][0]:
                                sequence_token = describe_response['logStreams'][0]['uploadSequenceToken']

                    timestamp = int(round(time.time() * 1000))

                    if create_log_stream:
                        client.create_log_stream(logGroupName=LOG_GROUP_NAME, logStreamName=log_stream_name)

                        log_response = client.put_log_events(
                            logGroupName=LOG_GROUP_NAME,
                            logStreamName=log_stream_name,
                            logEvents=[
                                {
                                    'timestamp': timestamp,
                                    'message': time.strftime('%Y-%m-%d %H:%M:%S') + "\t" + sns_record['Message']
                                }
                            ]
                        )
                    else:
                        log_response = client.put_log_events(
                            logGroupName=LOG_GROUP_NAME,
                            logStreamName=log_stream_name,
                            logEvents=[
                                {
                                    'timestamp': timestamp,
                                    'message': time.strftime('%Y-%m-%d %H:%M:%S') + "\t" + sns_record['Message']
                                }
                            ],
                            sequenceToken=sequence_token
                        )
            
    except Exception as e:
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)

        logger.error(f'AMI Orchestrator Reconciliation Notifier error: {str(e)}')

        raise ValueError(e)
