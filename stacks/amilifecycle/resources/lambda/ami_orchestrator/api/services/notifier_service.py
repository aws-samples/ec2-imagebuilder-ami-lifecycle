#!/usr/bin/env python

"""
    notifier_service.py:
    service that provides functionalities for interacting with SNS topics
    that are used for AMI Lifecycle communication channels.
"""

import json
import logging
import os
from os.path import abspath, dirname

import boto3
import jinja2
import yaml

from ..services.aws_api_service import AwsApiService
from ..services.database_service import DatabaseService

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

class NotifierService:
    """
        Service that provides functionalities for interacting with SNS topics
        that are used for AMI Lifecycle communication channels.
    """

    client = boto3.client('sns')

    TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
    EVENT_NOTIFICATION_LAMBDA_ARN = os.environ['EVENT_NOTIFICATION_LAMBDA_ARN']

    database_service = DatabaseService()
    awsapi_service = AwsApiService()

    TEMPLATE_DIR = dirname(dirname(abspath(__file__)))
    TEMPLATE_LOADER = jinja2.FileSystemLoader(searchpath=f"{TEMPLATE_DIR}/templates")
    TEMPLATE_ENV = jinja2.Environment(
        loader=TEMPLATE_LOADER,
        autoescape=jinja2.select_autoescape(
            default_for_string=True,
            default=True
        )
    )

    def _list_subscription(self, endpoint) -> str:
        response = self.client.list_subscriptions_by_topic(
            TopicArn=self.TOPIC_ARN
        )

        for subscription in response['Subscriptions']:
            if subscription['Endpoint'] == endpoint:
                return subscription['SubscriptionArn']

        return None

    def _get_filter_policy(self, subscription_arn, lifecycle_id) -> dict:
        if subscription_arn is None:
            return {"lifecycle_id": [f"{lifecycle_id}"]}

        # add lifecycle_id to exisiting subscription
        response = self.client.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )

        if 'Attributes' in response:
            if 'FilterPolicy' in response['Attributes']:
                filter_policy = json.loads(response['Attributes']['FilterPolicy'])
                filter_policy['lifecycle_id'].append(lifecycle_id)
                return filter_policy

        return {"lifecycle_id": [f"{lifecycle_id}"]}

    
    def create_email_subscription(self, protocol, endpoint, lifecycle_id) -> bool:
        
        subscription_arn = self._list_subscription(endpoint)
        
        if subscription_arn is None or not subscription_arn.startswith("arn:aws:sns"):
            subscription_arn = self.client.subscribe(
                TopicArn=self.TOPIC_ARN,
                Protocol=protocol.lower(),
                Endpoint=endpoint,
                ReturnSubscriptionArn=True
            )['SubscriptionArn']

            filter_policy = self._get_filter_policy(
                subscription_arn=None, 
                lifecycle_id=lifecycle_id
            )

            filter_policy_response = self.client.set_subscription_attributes(
                SubscriptionArn=subscription_arn,
                AttributeName = 'FilterPolicy', 
                AttributeValue = json.dumps(filter_policy)
            )

            return True
                    
        # filter the topic so only notifications related to the lifecycle id 
        # are sent to the endpoints
        
        filter_policy = self._get_filter_policy(
            subscription_arn=subscription_arn, 
            lifecycle_id=lifecycle_id
        )

        filter_policy_response = self.client.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName = 'FilterPolicy', 
            AttributeValue = json.dumps(filter_policy)
        )

        return True


    def create_lambda_subscription(self, lifecycle_id) -> str:

        protocol = "lambda"
        
        subscription_arn = self._list_subscription(self.EVENT_NOTIFICATION_LAMBDA_ARN)
        
        if subscription_arn is None or not subscription_arn.startswith("arn:aws:sns"):
            subscription_arn = self.client.subscribe(
                TopicArn=self.TOPIC_ARN,
                Protocol=protocol.lower(),
                Endpoint=self.EVENT_NOTIFICATION_LAMBDA_ARN,
                ReturnSubscriptionArn=True
            )['SubscriptionArn']

            filter_policy = self._get_filter_policy(
                subscription_arn=None, 
                lifecycle_id=lifecycle_id
            )

            filter_policy_response = self.client.set_subscription_attributes(
                SubscriptionArn=subscription_arn,
                AttributeName = 'FilterPolicy', 
                AttributeValue = json.dumps(filter_policy)
            )

            return True
                    
        # filter the topic so only notifications related to the lifecycle id 
        # are sent to the endpoints
        
        filter_policy = self._get_filter_policy(
            subscription_arn=subscription_arn, 
            lifecycle_id=lifecycle_id
        )

        filter_policy_response = self.client.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName = 'FilterPolicy', 
            AttributeValue = json.dumps(filter_policy)
        )

        return True


    def send_notification(self, subject, template_name, template_attributes) -> None:
        TEMPLATE_FILE = template_name
        template = self.TEMPLATE_ENV.get_template(TEMPLATE_FILE)
        message = template.render(vars=template_attributes)

        self.client.publish(
            TopicArn = self.TOPIC_ARN,
            Subject = subject[:98],
            Message = message,
            MessageAttributes = {
                'lifecycle_id': {
                    'DataType': 'String.Array',
                    'StringValue': f"[\"{template_attributes['lifecycle_id']}\"]"
                }
            }
        )


    def send_event_notification(
            self,
            operator: str,
            definition: dict,
            template_file: str
        ) -> None:
         # notification
        lifecycle_status_api = self.awsapi_service.get_ami_status_endpoint(definition['lifecycle_id'])

        # prepare the attributes for the message template
        template_attributes = {}
        template_attributes['operator'] = operator
        template_attributes['lifecycle_id'] = definition['lifecycle_id']
        template_attributes['stack_tag'] = definition['stack_tag']
        template_attributes['status_url'] = lifecycle_status_api
        template_attributes['formatted_event'] = yaml.dump(self.database_service.get_lifecycle_by_lifecycle_id(definition['lifecycle_id']), indent=2)
        
        # add custo attributes if WARN, ERROR or INFO
        if 'warning' in definition:
            template_attributes['warning'] = definition['warning']
        if 'error' in definition:
            template_attributes['error'] = definition['error']
        if 'info_message' in definition:
            template_attributes['info_message'] = definition['info_message']

        subject = f"{operator} event for {definition['stack_tag']}"

        # send the notification
        self.send_notification(
            subject=subject, 
            template_name=template_file, 
            template_attributes=template_attributes
        )
 
    def send_notification_without_message_attributes(
            self, 
            subject, 
            template_name, 
            template_attributes,
            sns_topic_arn
        ) -> None:
        TEMPLATE_FILE = template_name
        template = self.TEMPLATE_ENV.get_template(TEMPLATE_FILE)
        message = template.render(vars=template_attributes)

        self.client.publish(
            TopicArn = sns_topic_arn,
            Subject = subject[:98],
            Message = message
        )
