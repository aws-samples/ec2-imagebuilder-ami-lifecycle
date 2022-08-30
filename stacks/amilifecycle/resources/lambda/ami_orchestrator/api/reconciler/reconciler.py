#!/usr/bin/env python

"""
    reconciler.py: 
    a reconciller lambda that is executed periodically
    to verify that the tags written to the AMI Lifecycle 
    AMIs match the corresponding values in DynamoDB.
    DynamoDB is always the source of truth and the AMI tags
    should reflect the DynamoDB values.
"""

import json
import logging
import os
import traceback

import boto3

from ..services.database_service import DatabaseService
from ..services.notifier_service import NotifierService
from ..services.reconciliation_service import ReconciliationService

# constants
OPERATOR = "DB_KEY_TO_AMI_TAG_RECONCILER"
ERROR_TEMPLATE_FILE = "reconciliation_error.template"

# environment variables
RECONCILER_SNS_TOPIC_ARN = os.environ['RECONCILER_SNS_TOPIC_ARN']
STACK_TAG = os.environ['STACK_TAG']

# set logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

notifier_service = NotifierService()
database_service = DatabaseService()
reconciliation_service = ReconciliationService()

sns_client = boto3.client('sns')


def publish_to_sns(reconciliation_statuses: list) -> None:

    subject = "DB Keys to AMI Tags reconciler error report"

    sns_client.publish(
        TopicArn = RECONCILER_SNS_TOPIC_ARN,
        Subject = subject[:98],
        Message = json.dumps(reconciliation_statuses, indent=2),
    )


def lambda_handler(event, context):

    # print the event details
    logger.debug(json.dumps(event, indent=2))

    try:

        logger.info("Reconciler invocation")

        # get all the lifecycles managed by this deployment
        deployment_lifecycles = database_service.get_lifecycles_by_stack_tag(STACK_TAG)

        detected_reconciliation_errors = []

        for lifecycle in deployment_lifecycles:    
            # get the expected db keys and ami tags per lifecycle
            db_keys_to_ami_tags_map = reconciliation_service.get_db_keys_to_ami_tags(lifecycle)

            # get the ami_tag details for this lifecycle
            ami_tag_details = reconciliation_service.get_ami_tags(
                image_name=db_keys_to_ami_tags_map['ami_name']
            )

            # reconcile the tags
            error_reports = reconciliation_service.reconcile_db_keys_to_tags(
                lifecycle_id=lifecycle['lifecycle_id'],
                db_keys_to_ami_tags_map=db_keys_to_ami_tags_map,
                ami_tag_details=ami_tag_details
            )

            if error_reports is not None:

                # handle errors
                logger.info(f"{len(error_reports)} reconciliation errors detected. Attempting remediation.")
                logger.debug(json.dumps(error_reports, indent=2))

                detected_reconciliation_errors.append(error_reports)
                repairable_tags = []
                
                if len(error_reports['error_missing_tag_keys']) > 0:
                    ami_name = error_reports['error_missing_tag_keys'][0]['ami_name']
                else:
                    ami_name = error_reports['error_missing_tag_values'][0]['ami_name']

                # reconcile missing tags
                for reconciliation_error in error_reports['error_missing_tag_keys']:
                    repairable_tags.append(
                        {
                            'Key': reconciliation_error['missing_tag'],
                            'Value': reconciliation_error['expected_tag_value']
                        }
                    )
                # reconcile missing values
                for reconciliation_error in error_reports['error_missing_tag_values']:
                    repairable_tags.append(
                        {
                            'Key': reconciliation_error['tag_key'],
                            'Value': reconciliation_error['expected_tag_value']
                        }
                    )

                # fix the missing tags
                logger.info(f"Attempting remediation ami: {ami_name}")
                reconciliation_service.repair_missing_tags(
                    image_name=ami_name,
                    tags_to_write=repairable_tags
                )
                logger.info(f"Remediation completed without errors for ami: {ami_name}")

        return_msg = ""
        if len(detected_reconciliation_errors) > 0:
            logger.debug(
                f"Publishing {len(detected_reconciliation_errors)} detected reconciliation errors " +
                f"to sns topic: {RECONCILER_SNS_TOPIC_ARN}"
            )
            publish_to_sns(detected_reconciliation_errors)
            return_msg = f"Completed with resolved reconciliation errors for {len(detected_reconciliation_errors)} lifecycles."
        else:
            logger.debug(
                f"No detected reconciliation errors. Publishing empty report " +
                f"to sns topic: {RECONCILER_SNS_TOPIC_ARN}"
            )
            publish_to_sns(
                [
                    {
                        "reconciliation_status": "No reconciliation errors detected."
                    }
                ]
            )
            return_msg = "Completed with no reconciliation errors detected."

        return {
            'statusCode': 200,
            'body': { "message": return_msg },
            'headers': {'Content-Type': 'application/json'}
        }
        
    except Exception as e:
        
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)

        logger.error(f'{OPERATOR} error: {str(e)}')

        # prepare the attributes for the message template
        template_attributes = {}
        template_attributes['operator'] = OPERATOR

        # definition is not defined
        template_attributes['lifecycle_id'] = "MULTIPLE"
        template_attributes['stack_tag'] = STACK_TAG
        template_attributes['status_url'] = "NOT_APPLICABLE"
        template_attributes['error'] = {"error": str(e)}

        subject = f"ERROR in {OPERATOR}"

        # send the notification
        notifier_service.send_notification_without_message_attributes(
            subject=subject, 
            template_name=ERROR_TEMPLATE_FILE, 
            template_attributes=template_attributes,
            sns_topic_arn=RECONCILER_SNS_TOPIC_ARN
        )

        return {
            'statusCode': 500,
            'body': json.dumps({"error": str(e)}),
            'headers': {'Content-Type': 'application/json'}
        }
