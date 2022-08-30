#!/usr/bin/env python

"""
    event_notifications.py: 
    Lambda that subscribes to an SNS topic. The SNS topic receives AMI lifecycle
    event notifications which this lambda function then writes to a CloudWatch LogGroup 
"""

import json
import logging
import os
import time
import traceback

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

                    if 'MessageAttributes' in sns_record:
                        if 'lifecycle_id' in sns_record['MessageAttributes']:
                            lifecycle_id = json.loads(
                                sns_record['MessageAttributes']['lifecycle_id']['Value']
                            )[0]
                
                            # check if the log stream exists
                            describe_response = client.describe_log_streams(
                                logGroupName=LOG_GROUP_NAME,
                                logStreamNamePrefix=lifecycle_id,
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
                                client.create_log_stream(logGroupName=LOG_GROUP_NAME, logStreamName=lifecycle_id)

                                log_response = client.put_log_events(
                                    logGroupName=LOG_GROUP_NAME,
                                    logStreamName=lifecycle_id,
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
                                    logStreamName=lifecycle_id,
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

        logger.error(f'AMI Lifecycle Event Notification error: {str(e)}')

        raise ValueError(e)
