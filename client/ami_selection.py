#!/usr/bin/env python

"""
    ami_selection.py:
    Provides an AMI Selection Criteria class which is used to define
    the criteria to be used during AMI selection.
    Provides an AMI Selection class that can be used to perform an
    AMI lookup and obtain an AMI id according to an AMI Selection Criteria.
"""

import functools
import json
import logging

import boto3
import semver
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from botocore.exceptions import ClientError

from ami_selection_utils import AmiSelectionUtils

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


class AmiSelectionCriteria:
    """Defines the criteria to be used during AMI selection."""

    # version options
    LATEST = "latest"
    ANY = "any"
    CREATED = "ami-creation"
    PATCHED = "ami-patch"

    # event options
    AMI_WITH_OS_HARDENING = "AMI_WITH_OS_HARDENING"
    SMOKE_TESTED = "SMOKE_TESTED"
    VULNERABILITY_SCANNED = "VULNERABILITY_SCANNED"
    QA_CERTIFICATION_REQUESTED = "QA_CERTIFICATION_REQUESTED"
    QA_CERTIFIED = "QA_CERTIFIED"
    PRODUCTION_APPROVED = "PRODUCTION_APPROVED"

    def __init__(
            self,
            stack_tag: str,
            ami_semver: str,
            product_ver: str,
            product_name: str,
            commit_ref: str,
            lifecycle_type: str,
            lifecycle_event: str,
            aws_region: str
        ) -> None:
        self.stack_tag = stack_tag
        self.ami_semver = ami_semver
        self.product_ver = product_ver
        self.product_name = product_name
        self.commit_ref = commit_ref
        self.lifecycle_type = lifecycle_type
        self.lifecycle_event = lifecycle_event
        self.aws_region = aws_region

    def to_json(self) -> str:
        """JSON representation of the AMI selection criteria."""
        return json.dumps(
            {
                "stack_tag": self.stack_tag,
                "ami_semver": self.ami_semver,
                "product_ver": self.product_ver,
                "product_name": self.product_name,
                "commit_ref": self.commit_ref,
                "lifecycle_type": self.lifecycle_type,
                "lifecycle_event": self.lifecycle_event,
                "aws_region": self.aws_region
            }, indent=2
        )


class AmiSelection:
    """Selects an AMI based upon an AmiSelectionCriteria."""

    serializer= TypeSerializer()
    deserializer = TypeDeserializer()

    ami_selection_utils = AmiSelectionUtils()

    # scores assiociated to events that are used during lookup operations.
    # these scores directly correspond to the event scoring system defined in the
    # poc-aio AmiOrchestrator stack so any changes made here must be reflected in the
    # poc-aio AmiOrchestrator stack
    EVENT_SCORES = {
        "AMI_WITH_OS_HARDENING": 1,
        "SMOKE_TESTED": 2,
        "VULNERABILITY_SCANNED": 2,
        "QA_CERTIFICATION_REQUESTED": 4,
        "QA_CERTIFIED": 4,
        "PRODUCTION_APPROVED": 6
    }

    AMISELECTION_TABLENAME = "amiSelectionTableName"


    def _build_filter_expression(
            self,
            ami_selection_options: AmiSelectionCriteria
        ) -> str:
        """
            Builds the dynamodb FilterExpression and ExpressionAttributeValues
            from an AmiSelectionCriteria object to be used in a dynamodb scan operation
            during AMI lookup
        """

        filter_expression_list = []
        expression_attribute_values = {}
        count = 1

        # stack_tag
        # NOTE: this is the KeyCondition so it must not be added to the filter expression
        if ami_selection_options.stack_tag is not None:
            expression_attribute_values[f":v{count}"] = {
                'S': ami_selection_options.stack_tag
            }
            count = count + 1
        else:
            raise ValueError(
                "stack_tag was not provided. " +
                "stack_tag is the query key condition and a mandatory requirement."
            )

        # ami_semver
        if ami_selection_options.ami_semver not in [
                None,
                AmiSelectionCriteria.LATEST
            ]:
            filter_expression_list.append(f"ami_semver = :v{count}")
            expression_attribute_values[f":v{count}"] = {
                'S': ami_selection_options.ami_semver
            }
            count = count + 1

        # product_ver
        if ami_selection_options.product_ver not in [
                None,
                AmiSelectionCriteria.ANY
            ]:
            filter_expression_list.append(f"product_ver = :v{count}")
            expression_attribute_values[f":v{count}"] = {
                'S': ami_selection_options.product_ver
            }
            count = count + 1

        # product_name
        if ami_selection_options.product_name not in [
                None,
                AmiSelectionCriteria.ANY
            ]:
            filter_expression_list.append(f"product_name = :v{count}")
            expression_attribute_values[f":v{count}"] = {
                'S': ami_selection_options.product_name
            }
            count = count + 1

        # commit_ref
        if ami_selection_options.commit_ref not in [
                None,
                AmiSelectionCriteria.ANY
            ]:
            filter_expression_list.append(f"commit_ref = :v{count}")
            expression_attribute_values[f":v{count}"] = {
                'S': ami_selection_options.commit_ref
            }
            count = count + 1

        # lifecycle_type
        if ami_selection_options.lifecycle_type in [
                AmiSelectionCriteria.CREATED,
                AmiSelectionCriteria.PATCHED,
            ]:
            filter_expression_list.append(f"lifecycle_type = :v{count}")
            expression_attribute_values[f":v{count}"] = {
                'S': ami_selection_options.lifecycle_type
            }
            count = count + 1

        # lifecycle_event
        if ami_selection_options.lifecycle_event is not None:
            filter_expression_list.append(f"lifecycle_score >= :v{count}")
            expression_attribute_values[f":v{count}"] = {
                'N': str(self.EVENT_SCORES[ami_selection_options.lifecycle_event])
            }
            count = count + 1
           
        # aws_region
        if ami_selection_options.aws_region is not None:
            filter_expression_list.append(f"aws_region = :v{count}")
            expression_attribute_values[f":v{count}"] = {
                'S': ami_selection_options.aws_region
            }
            count = count + 1

        return ' and '.join(filter_expression_list), expression_attribute_values


    def _semver_compare(self, x, y) -> int:
        return semver.compare(x['ami_semver'], y['ami_semver'])


    def _get_ami_id(
            self,
            ami_selection_options: AmiSelectionCriteria,
            region: str
        ) -> str:
        """
            Selects an AMI based on the provided AmiSelectionCritera.
            The AmiSelectionCritera is converted to dynamodb FilterExpression
            and ExpressionAttributeValues representations which are used in a
            dynamodb scan operation.
            When multiple results are returned from dynamodb, the AMI with the
            highest AMI Sematic Version is returned.
        """
        try:
            filter_expression, expression_attribute_values = self._build_filter_expression(
                                                                ami_selection_options
                                                            )

            output_keys = self.ami_selection_utils.get_cloudformation_outputs(
                    stack_name="AmiLifecycle",
                    region=region
                )

            table_name = output_keys[self.AMISELECTION_TABLENAME]

            # create service client using the assumed role credentials
            dynamodb_client = boto3.client('dynamodb', region_name=region)

            response = dynamodb_client.query(
                TableName=table_name,
                ExpressionAttributeValues=expression_attribute_values,
                IndexName="stack_tag_index",
                KeyConditionExpression='stack_tag = :v1',
                FilterExpression=filter_expression
            )

            if 'Items' in response:
                if len(response['Items']) > 0:
                    serialized_items = []
                    for item in response['Items']:
                        serialized_items.append(
                            {
                                'M': item
                            }
                        )
                    serialized_data = {
                        'L': serialized_items
                    }
                    deserialized_data = self.deserializer.deserialize(serialized_data)

                    # The results of the dynamodb scan are sorted in descending order
                    # based on the AMI Semantic version. This means that the object
                    # at the head of the list (e.g. list[0]) has the highest AMI semantic version
                    # and the object at the tail of the list (e.g list(len(list)-1)) has the lowest
                    # AMI semantic version
                    sorted_list = sorted(
                        deserialized_data,
                        key=functools.cmp_to_key(self._semver_compare),
                        reverse=True
                    )
                    retieved_ami = sorted_list[0]
                    logger.debug(f"Retrieved AMI lookup: {retieved_ami}")
                    # lifecycle_score is an int which is stored as a Decimal
                    # Decimal cannot be natively converted with json.dumps
                    # therefore we just convert the Decimal to int
                    # a convertor class is the cannonical way to solve this issue
                    # but would be overkill in this scenario
                    retieved_ami['lifecycle_score'] = int(retieved_ami['lifecycle_score'])
                    logger.debug(json.dumps(retieved_ami, indent=2))
                    return retieved_ami['ami_id']

            return None

        except Exception as e:
            logger.error(str(e))
            raise ClientError(str(e))


    def get_ami_id(
            self,
            stack_tag: str,
            ami_semver: str,
            product_ver: str,
            product_name: str,
            commit_ref: str,
            lifecycle_type: str,
            lifecycle_event: str,
            aws_region: str
        ) -> str:
        ami_id = None

        ami_selection_options = AmiSelectionCriteria(
            stack_tag=stack_tag,
            ami_semver=ami_semver,
            lifecycle_event=lifecycle_event,
            aws_region=aws_region,
            product_ver=product_ver,
            product_name=product_name,
            commit_ref=commit_ref,
            lifecycle_type=lifecycle_type
        )
                
        ami_id = self._get_ami_id(
            ami_selection_options=ami_selection_options, 
            region=aws_region
        )

        if not ami_id:
            error_msg = (
                "Unable to obtain AMI ID with AmiSelectionCriteria: " +
                ami_selection_options.to_json()
            )
            logger.error(error_msg)
            raise ValueError(error_msg)
            
        return ami_id
