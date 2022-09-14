#!/usr/bin/env python

"""
    qa_notifier_service.py:
    Service that sends external QA notifications to a SNS topic.
"""

import logging
import os
from os.path import abspath, dirname

import boto3
import jinja2

from ..services.constants_service import ConstantsService
from ..services.security_service import SecurityService

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

class QANotifierService:

    sns_client = boto3.client('sns')

    QA_SNS_TOPIC = os.environ['QA_SNS_TOPIC']

    constants_service = ConstantsService()
    security_service = SecurityService()

    TEMPLATE_DIR = dirname(dirname(abspath(__file__)))
    TEMPLATE_LOADER = jinja2.FileSystemLoader(searchpath=f"{TEMPLATE_DIR}/templates")
    TEMPLATE_ENV = jinja2.Environment(
        loader=TEMPLATE_LOADER,
        autoescape=jinja2.select_autoescape(
            default_for_string=True,
            default=True
        )
    )


    def send_email_notification(self, subject, template_name, template_attributes) -> None:
        TEMPLATE_FILE = template_name
        template = self.TEMPLATE_ENV.get_template(TEMPLATE_FILE)
        
        message = template.render(vars=template_attributes)

        self.sns_client.publish(
            TopicArn = self.QA_SNS_TOPIC,
            Subject = subject[:98],
            Message = message,
            MessageAttributes = {
                'lifecycle_id': {
                    'DataType': 'String.Array',
                    'StringValue': f"[\"{template_attributes['properties']['lifecycle_id']}\"]"
                }
            }
        )
