#!/usr/bin/env python

"""
    error_notifier_service.py:
    Service that sends State Machine errors to a SNS topic.
"""

import json
import logging
import os
import traceback
from os.path import abspath, dirname

import boto3
import jinja2
import yaml

from ..services.constants_service import ConstantsService
from ..services.security_service import SecurityService

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

class ErrorNotifierService:

    sns_client = boto3.client('sns')
    sqs_client = boto3.client('sqs')

    NOTIFICATION_SNS_TOPIC_ARN = os.environ['NOTIFICATION_SNS_TOPIC_ARN']
    ERROR_QUEUE_URL = os.environ['API_ERROR_QUEUE_URL']

    constants_service = ConstantsService()
    security_service = SecurityService()

    TEMPLATE_DIR = dirname(dirname(abspath(__file__)))
    TEMPLATE_LOADER = jinja2.FileSystemLoader(searchpath=f"{TEMPLATE_DIR}/templates")
    TEMPLATE_ENV = jinja2.Environment(loader=TEMPLATE_LOADER)


    def __send_email_notification(self, subject, template_name, template_attributes) -> None:
        TEMPLATE_FILE = template_name
        template = self.TEMPLATE_ENV.get_template(TEMPLATE_FILE)
        template_attributes['formatted_output'] = yaml.dump(template_attributes)

        message = template.render(vars=template_attributes)

        self.sns_client.publish(
            TopicArn = self.NOTIFICATION_SNS_TOPIC_ARN,
            Subject = subject[:98],
            Message = message,
            MessageAttributes = {
                'lifecycle_id': {
                    'DataType': 'String.Array',
                    'StringValue': f"[\"{template_attributes['properties']['lifecycle_id']}\"]"
                }
            }
        )

    
    def __send_sqs_notification(self, error_message, stack_trace, template_attributes) -> None:
        message_body = {
            "lifecycle_id": template_attributes['properties']['lifecycle_id'],
            "api_key": self.security_service.get_ami_error_receiver_api_key(),
            "status": self.constants_service.STATUS_ERROR,
            "status_date": template_attributes['status_date'],
            "error_message": error_message,
            "stack_trace": stack_trace
        }

        response = self.sqs_client.send_message(
            QueueUrl=self.ERROR_QUEUE_URL,
            MessageBody=json.dumps(message_body, separators=(',', ':'))
        )


    def send_notification(
            self,
            subject,
            template_name,
            template_attributes,
            error_message,
            stack_trace
        ) -> None:
        try:
            self.__send_email_notification(subject, template_name, template_attributes)
            self.__send_sqs_notification(error_message, stack_trace, template_attributes)
        except Exception as e:
            traceback.print_exception(type(e), value=e, tb=e.__traceback__)
            logger.error(f"An error occurred attempting to send error notification: {str(e)}")
