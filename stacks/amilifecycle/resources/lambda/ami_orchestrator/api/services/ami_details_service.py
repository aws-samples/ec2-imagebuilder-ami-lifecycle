#!/usr/bin/env python

"""
    ami_details_service.py:
    service which obtains details about AMIs and writes
    tags to AMIs. This service is capable of assuming
    the cross-account role created by the AmiLifecylceTagger stack
    and reading and writing tags to/from AMIs in other accounts.
    The service provides the capability to ensure that AMI tags
    are consistent across multiple AMIs in different accounts/regions.
"""

import datetime
import json
import logging
import os

import boto3

from .constants_service import ConstantsService
from .lifecycle_service import LifecycleService

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

class AmiDetailsService:
    """
        Service which obtains details about AMIs and writes
        tags to AMIs. This service is capable of assuming
        the cross-account role created by the AmiLifecylceTagger stack
        and reading and writing tags to/from AMIs in other accounts.
        The service provides the capability to ensure that AMI tags
        are consistent across multiple AMIs in different accounts/regions.
    """

    constants_service = ConstantsService()
    lifecycle_service = LifecycleService()

    # TOOLING and SHARED SERVICES account id values
    # are provided for use cases with multi-account deployments
    TOOLING_ACCOUNT_ID = os.environ['TOOLING_ACCOUNT_ID']
    SHARED_SERVICES_ACCOUNT_ID = os.environ['SHARED_SERVICES_ACCOUNT_ID']
    DISTRIBUTION_ACCOUNTS = os.environ['DISTRIBUTION_ACCOUNTS'].split(',')
    DISTRIBUTION_REGIONS = os.environ['DISTRIBUTION_REGIONS'].split(',')
    AMI_TAGGER_ROLE_NAME = os.environ['AMI_TAGGER_ROLE_NAME']
    DEFAULT_AMI_SEMVER_SEED = os.environ['DEFAULT_AMI_SEMVER_SEED']
    RUNTIME_REGION = os.environ['AWS_REGION']

    EC2_CLIENT = boto3.client('ec2')

    BOTO3_STS_SESSIONS = {}

    def get_service_name(self) -> str:
        return "ami details service"

    def _get_assumed_session(self, distribution_account_id: str) -> boto3.Session:
        """aws sts assume-role --role-arn arn:aws:iam::00000000000000:role/example-role --role-session-name example-role"""

        # return session for distribution account if we already have it
        if distribution_account_id in self.BOTO3_STS_SESSIONS:
            return self.BOTO3_STS_SESSIONS[distribution_account_id]
        
        # we don't have an exisitng session so we will create one
        role_arn=f"arn:aws:iam::{distribution_account_id}:role/{self.AMI_TAGGER_ROLE_NAME}"

        sts_client = boto3.client('sts')
        response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="AMI-TAGGING-OP")
        session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )
        logger.debug(f"Assumed role ARN is: {response['AssumedRoleUser']['Arn']}")
        self.BOTO3_STS_SESSIONS[distribution_account_id] = session

        logger.debug("Current boto3 sessions:")
        logger.debug(self.BOTO3_STS_SESSIONS)

        return session

    
    def _get_ami_details_by_image_name(
            self, 
            image_name: str, 
            cross_account_ami: bool, 
            distribution_account: str, 
            distribution_region: str
        ) -> list:
        
        if cross_account_ami == False:
            response = self.EC2_CLIENT.describe_images(
                Filters=[
                    {
                        'Name': 'name',
                        'Values': [image_name]
                    }
                ],
                IncludeDeprecated=False
            )
        # else we need to assume a role
        else:
            sts_session = self._get_assumed_session(distribution_account)
            sts_ec2_client = sts_session.client('ec2', region_name=distribution_region)

            response = sts_ec2_client.describe_images(
                Filters=[
                    {
                        'Name': 'name',
                        'Values': [image_name]
                    }
                ],
                IncludeDeprecated=False
            )

        if len(response['Images']) == 0:
            if cross_account_ami == False:
                raise ValueError(f"Unable to find AMI with name {image_name}. Looking in tooling account {self.TOOLING_ACCOUNT_ID} in region {self.RUNTIME_REGION}.")
            else:
                raise ValueError(f"Unable to find AMI with name {image_name}. Looking in account {distribution_account} in {distribution_region}.")

        if cross_account_ami == False:
            owner_id = self.TOOLING_ACCOUNT_ID
            ami_region = self.RUNTIME_REGION
            ami_priority = "MAIN"
        else:
            owner_id = distribution_account
            ami_region = distribution_region
            ami_priority = "DISTRIBUTED"

        # defensive checks
        ami_id = "Undefined"
        ami_state = "Undefined"
        ami_description = "Undefined"
        ami_tags = []
        ami_location = "Undefined"
        ami_type = "Undefined"
        ami_architecture = "Undefined"
        ami_creation_date = "Undefined"
        is_ami_public = True
        ami_platform_details = "Undefined"
        ami_virtualization_type = "Undefined"

        ami_properties_list = []

        if "Images" in response:
            if len(response['Images']) > 0:
                for ami_details in response['Images']:
                    ami_id = "Unknown" if 'ImageId' not in ami_details else ami_details['ImageId']
                    ami_state = "Unknown" if 'State' not in ami_details else ami_details['State']
                    ami_description = "Unknown" if 'Description' not in ami_details else ami_details['Description']
                    ami_tags = [] if 'Tags' not in ami_details else ami_details['Tags']
                    ami_location = "Unknown" if 'ImageLocation' not in ami_details else ami_details['ImageLocation']
                    ami_type = "Unknown" if 'ImageType' not in ami_details else ami_details['ImageType']
                    ami_architecture = "Unknown" if 'Architecture' not in ami_details else ami_details['Architecture']
                    ami_creation_date = "Unknown" if 'CreationDate' not in ami_details else ami_details['CreationDate']
                    is_ami_public = True if 'Public' not in ami_details else ami_details['Public']
                    ami_platform_details = "Unknown" if 'PlatformDetails' not in ami_details else ami_details['PlatformDetails']
                    ami_virtualization_type = "Unknown" if 'VirtualizationType' not in ami_details else ami_details['VirtualizationType']

                    ami_properties = {
                        "ownerId": owner_id,
                        "ami_region": ami_region,
                        "ami_priority": ami_priority,
                        "ami_id": ami_id,
                        "ami_state": ami_state,
                        "ami_description": ami_description,
                        "ami_tags": ami_tags,
                        "ami_location": ami_location,
                        "ami_type": ami_type,
                        "ami_architecture": ami_architecture,
                        "ami_creation_date": ami_creation_date,
                        "is_ami_public": is_ami_public,
                        "ami_platform_details": ami_platform_details,
                        "ami_virtualization_type": ami_virtualization_type
                    }

                    ami_properties_list.append(ami_properties)

        return ami_properties_list


    def _validate_tags_consistency(self, ami_ids: list, ami_tags: list) -> bool:
        # we expect at least 2 sets of ami_tags, for AMI in tooling and shared services account
        if len(ami_tags) < 2:
            raise ValueError(f"Expected at least 2 sets of ami_tags but actual ami_tags number is: {len(ami_tags)} composed of {ami_tags}")

        # make sure that the image tags are consistent across all images

        # grab the first tag set and use this as the base for comparison
        source_tag_set = ami_tags[0]
        
        # compare the source tag set against all the others
        compare_tag_set = ami_tags[1:]
        
        # compare keys for consistency
        for source_tag in source_tag_set:
            # only compare tags related to AMI lifecycle processes
            if self.constants_service.AMI_LIFECYCLE_TAG_PREFIX in source_tag['Key']:
                for compare_tag in compare_tag_set:
                    # raise an error if there is a Key mismatch
                    compare_keys = [compare_key['Key'] for compare_key in compare_tag]
                    if source_tag['Key'] not in compare_keys:
                        msg = (
                            f"Detected a difference between AMI tags for ami_ids: {','.join(ami_ids)}. " +
                            f"Key {source_tag['Key']} not consistent across AMIs. " +
                            f"Source key {source_tag['Key']} is not present in comparison tag set: " +
                            ",".join(compare_keys)
                        )
                        raise ValueError(msg)
                
                    # raise an error if there is a Value mismatch
                    compare_values = [compare_value['Value'] for compare_value in compare_tag]
                    if source_tag['Value'] not in compare_values:
                        msg = (
                            f"Detected a difference between AMI tags for ami_ids: {','.join(ami_ids)}. " +
                            f"Key {source_tag['Key']} with Value {source_tag['Value']} not consistent across AMIs. " +
                            f"Source value {source_tag['Value']} is not present in comparison tag set: " +
                            json.dumps(compare_tag, indent=2)
                        )
                        raise ValueError(msg)

        return True


    def read_image_tags(self, image_name: str) -> list:
        ami_details = []
        ami_ids = []
        ami_tags = []
        
        # grab tags in the context of the original, non assumed session

        # get the ami id for the tooling account in the default region
        tooling_ami_details_list = self._get_ami_details_by_image_name(
                image_name=image_name, 
                cross_account_ami=False, 
                distribution_account=None,
                distribution_region=None
            )

        for tooling_ami_details in tooling_ami_details_list:
            ami_details.append(tooling_ami_details)
            ami_ids.append(tooling_ami_details['ami_id'])
            ami_tags.append(tooling_ami_details['ami_tags'])
        
        for distribution_account in self.DISTRIBUTION_ACCOUNTS:
            for region in self.DISTRIBUTION_REGIONS:
                # get the ami id for the shared services account in the supported region
                distribution_account_ami_details_list = self._get_ami_details_by_image_name(
                    image_name=image_name, 
                    cross_account_ami=True,
                    distribution_account=distribution_account,
                    distribution_region=region
                )

                for distribution_account_ami_details in distribution_account_ami_details_list:
                    ami_details.append(distribution_account_ami_details)
                    ami_ids.append(distribution_account_ami_details['ami_id'])
                    ami_tags.append(distribution_account_ami_details['ami_tags'])
            
        # will raise an error if the tags are not validated
        if self._validate_tags_consistency(ami_ids, ami_tags):
            # the tags are valid and consistent so we return the ami details
            return ami_details


    def get_ami_tags(self, image_name: str) -> list:
        ami_tags = []
        
        # grab tags in the context of the original, non assumed session

        # get the ami id for the tooling account in the default region
        tooling_ami_details_list = self._get_ami_details_by_image_name(
                image_name=image_name, 
                cross_account_ami=False, 
                distribution_account=None,
                distribution_region=None
            )

        for tooling_ami_details in tooling_ami_details_list:
            ami_tags.append(
                {
                    "ami_id": tooling_ami_details['ami_id'],
                    "ami_tags": tooling_ami_details['ami_tags'],
                    "ami_details": tooling_ami_details
                }
            )
        
        for distribution_account in self.DISTRIBUTION_ACCOUNTS:
            for region in self.DISTRIBUTION_REGIONS:
                # get the ami id for the shared services account in the supported region
                distribution_account_ami_details_list = self._get_ami_details_by_image_name(
                    image_name=image_name, 
                    cross_account_ami=True,
                    distribution_account=distribution_account,
                    distribution_region=region
                )

                for distribution_account_ami_details in distribution_account_ami_details_list:
                    ami_tags.append(
                        {
                            "ami_id": distribution_account_ami_details['ami_id'],
                            "ami_tags": distribution_account_ami_details['ami_tags'],
                            "ami_details": distribution_account_ami_details
                        }
                    )

        return ami_tags


    def _write_image_tag(
            self, 
            ami_id: str, 
            tags_to_write: list, 
            cross_account_ami: bool,
            distribution_account: str,
            distribution_region: str
        ) -> None:

        formatted_tags = []
        for tag_to_write in tags_to_write:
            formatted_tags.append(
                {
                    'Key': tag_to_write['Key'],
                    'Value': tag_to_write['Value'][:255]
                }
            )

        logger.debug(f"Tags to be written to AMI: {ami_id}")
        logger.debug(formatted_tags)
        
        if cross_account_ami == False:
            self.EC2_CLIENT.create_tags(
                Resources=[
                    ami_id
                ],
                Tags=formatted_tags
            )
        # else we need to assume a role
        else:
            sts_session = self._get_assumed_session(distribution_account)
            sts_ec2_client = sts_session.client('ec2', region_name=distribution_region)

            debug_msg = (
                f"Attempting to write tags for AMI {ami_id}, " +
                f"account {distribution_account} in region {distribution_region}"
            )

            logger.debug(debug_msg)
            logger.debug(sts_session)
            logger.debug(sts_ec2_client)

            sts_ec2_client.create_tags(
                Resources=[
                    ami_id
                ],
                Tags=formatted_tags
            )


    def write_image_tags(self, image_name: str, tags_to_write: list) -> list:

        tooling_acc_ami_details_list = self._get_ami_details_by_image_name(
            image_name=image_name, 
            cross_account_ami=False, 
            distribution_account=None,
            distribution_region=None
        )

        for tooling_acc_ami_details in tooling_acc_ami_details_list:
            self._write_image_tag(
                ami_id=tooling_acc_ami_details['ami_id'], 
                tags_to_write=tags_to_write,
                cross_account_ami=False,
                distribution_account=None,
                distribution_region=None
            )

        for distribution_account in self.DISTRIBUTION_ACCOUNTS:
            for region in self.DISTRIBUTION_REGIONS:
                # get the ami id for the distribution account in the supported region
                distribution_ami_details_list = self._get_ami_details_by_image_name(
                            image_name=image_name, 
                            cross_account_ami=True,
                            distribution_account=distribution_account,
                            distribution_region=region
                        )

                for distribution_ami_details in distribution_ami_details_list:
                    self._write_image_tag(            
                        ami_id=distribution_ami_details['ami_id'],
                        tags_to_write=tags_to_write,
                        cross_account_ami=True,
                        distribution_account=distribution_account,
                        distribution_region=region
                    )


        # read back the tags will will ensure that the tags on all images match
        return self.read_image_tags(image_name)

    
    def _write_tags_for_event_ami_build(
            self,
            lifecycle_id: str,
            image_name: str, 
            event_result: dict
        ) -> list:
        tag_prefix = self.constants_service.AMI_LIFECYCLE_TAG_PREFIX

        # grab some AMI_BUILD specific values for tagging
        components = []
        for component in event_result['properties']['imagebuilder_recipe_components']:
            # grab the component name and add to list
            components.append(component['componentArn'].partition("component/")[2])

        tags_to_write = [
            {
                "Key": f"{tag_prefix}_LIFECYCLE_ID",
                "Value": lifecycle_id
            },
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_STATUS",
                "Value": event_result['status']
            },
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_STATUS_DATE",
                "Value": event_result['status_date']
            },
            {
                "Key": f"{tag_prefix}_CURRENT_AMI_SEMVER",
                "Value": event_result['properties']['ami_details'][0]['ami_semver']
            },
            {
                "Key": f"{tag_prefix}_PRODUCT_VER",
                "Value": event_result['product_ver']
            },
            {
                "Key": f"{tag_prefix}_PRODUCT_NAME",
                "Value": event_result['product_name']
            },
            {
                "Key": f"{tag_prefix}_COMMIT_REF",
                "Value": event_result['commit_ref']
            },
            {
                "Key": f"{tag_prefix}_COMPONENTS",
                "Value": ",".join(components)
            },
            {
                "Key": f"{tag_prefix}_IMAGEBUILDER_IMAGE_ARN",
                "Value": event_result['properties']['imagebuilder_image_arn']
            },
            {
                "Key": f"{tag_prefix}_IMAGEBUILDER_RECIPE_ARN",
                "Value": event_result['properties']['imagebuilder_imagerecipe_arn']
            },
            {
                "Key": f"{tag_prefix}_IMAGEBUILDER_RECIPE_NAME",
                "Value": event_result['properties']['imagebuilder_imagerecipe_name']
            },
            {
                "Key": f"{tag_prefix}_IMAGEBUILDER_SRC_PIPELINE",
                "Value": event_result['properties']['imagebuilder_source_pipeline_name']
            }
        ]

        
        return self.write_image_tags(image_name, tags_to_write)


    def _write_tags_for_ami_smoke_tests(
            self,
            image_name: str, 
            event_result: dict
        ) -> list:
        tag_prefix = self.constants_service.AMI_LIFECYCLE_TAG_PREFIX

        tags_to_write = [
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_STATUS",
                "Value": event_result['status']
            },
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_STATUS_DATE",
                "Value": event_result['status_date']
            }
        ]
        
        return self.write_image_tags(image_name, tags_to_write)


    def _write_tags_for_ami_vulnerability_scans(
            self,
            image_name: str, 
            event_result: dict
        ) -> list:
        tag_prefix = self.constants_service.AMI_LIFECYCLE_TAG_PREFIX

        severities = event_result['properties']['vulnerability_severities'] 
        vulnerability_severities = (
            f"CRITICAL: {severities['CRITICAL']}, HIGH: {severities['HIGH']}, " +
            f"MEDIUM: {severities['MEDIUM']}, LOW: {severities['LOW']}, " +
            f"INFORMATIONAL: {severities['INFORMATIONAL']}, UNTRIAGED: {severities['UNTRIAGED']}"
        )

        vulnerability_scan_report = (
            f"s3://{event_result['properties']['vulnerability_scan_report']['S3Bucket']}/" +
            event_result['properties']['vulnerability_scan_report']['S3Key']
        )

        tags_to_write = [
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_STATUS",
                "Value": event_result['status']
            },
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_STATUS_DATE",
                "Value": event_result['status_date']
            },
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_TOTAL_VULNERABILITIES",
                "Value": event_result['properties']['total_vulnerabilities']
            },
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_SEVERITIES",
                "Value": vulnerability_severities
            },
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_SCAN_REPORT",
                "Value": vulnerability_scan_report
            }
        ]

        return self.write_image_tags(image_name, tags_to_write)


    def _write_tags_for_ami_create_qa_certification_request(
            self,
            image_name: str, 
            event_result: dict
        ) -> list:
        tag_prefix = self.constants_service.AMI_LIFECYCLE_TAG_PREFIX

        tags_to_write = [
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_STATUS",
                "Value": event_result['status']
            },
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_STATUS_DATE",
                "Value": event_result['status_date']
            },
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_EXPORT_IMAGE_ID",
                "Value": event_result['properties']['export_image_id']
            },
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_EXPORT_IMAGE_PATH",
                "Value": f"{event_result['properties']['export_image_path']}"
            },
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_EXPORT_IMAGE_TASK_ID",
                "Value": f"{event_result['properties']['export_image_task_id']}"
            }
        ]

        return self.write_image_tags(image_name, tags_to_write)


    def _write_tags_for_ami_create_qa_certification_response(
            self,
            image_name: str, 
            event_result: dict
        ) -> list:
        tag_prefix = self.constants_service.AMI_LIFECYCLE_TAG_PREFIX

        tags_to_write = [
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_STATUS",
                "Value": event_result['status']
            },
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_STATUS_DATE",
                "Value": event_result['status_date']
            },
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_QA_CERTIFICATION_STATUS",
                "Value": event_result['certification_status']
            }
        ]

        return self.write_image_tags(image_name, tags_to_write)


    def _write_tags_for_ami_mark_for_production(
            self,
            image_name: str, 
            event_result: dict
        ) -> list:
        tag_prefix = self.constants_service.AMI_LIFECYCLE_TAG_PREFIX

        s3_ami_backup_path = (
            f"s3://{event_result['properties']['s3_bucket']}/" +
            event_result['properties']['s3_object_key']
        )

        tags_to_write = [
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_STATUS",
                "Value": event_result['status']
            },
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_STATUS_DATE",
                "Value": event_result['status_date']
            },
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_APPROVAL_STATUS",
                "Value": event_result['properties']['approval_status']
            },
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_AMI_BACKUP",
                "Value": s3_ami_backup_path
            }
        ]

        return self.write_image_tags(image_name, tags_to_write)


    def _write_tags_for_event_ami_patch(
            self,
            image_name: str, 
            event_result: dict
        ) -> list:
        tag_prefix = self.constants_service.AMI_LIFECYCLE_TAG_PREFIX

        # grab some AMI_PATCH specific values for tagging
        components = []
        for component in event_result['properties']['imagebuilder_recipe_components']:
            # grab the component name and add to list
            components.append(component['componentArn'].partition("component/")[2])

        tags_to_write = [
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_STATUS",
                "Value": event_result['status']
            },
            {
                "Key": f"{tag_prefix}_EVENT_{event_result['name']}_STATUS_DATE",
                "Value": event_result['status_date']
            },
            {
                "Key": f"{tag_prefix}_CURRENT_AMI_SEMVER",
                "Value": event_result['properties']['ami_details'][0]['ami_semver']
            },
            {
                "Key": f"{tag_prefix}_AMI_ANCESTRY",
                "Value": event_result['ami_ancestry']
            },
            {
                "Key": f"{tag_prefix}_COMMIT_REF",
                "Value": event_result['commit_ref']
            },
            {
                "Key": f"{tag_prefix}_COMPONENTS",
                "Value": ",".join(components)
            },
            {
                "Key": f"{tag_prefix}_IMAGEBUILDER_IMAGE_ARN",
                "Value": event_result['properties']['imagebuilder_image_arn']
            },
            {
                "Key": f"{tag_prefix}_IMAGEBUILDER_RECIPE_ARN",
                "Value": event_result['properties']['imagebuilder_imagerecipe_arn']
            },
            {
                "Key": f"{tag_prefix}_IMAGEBUILDER_RECIPE_NAME",
                "Value": event_result['properties']['imagebuilder_imagerecipe_name']
            },
            {
                "Key": f"{tag_prefix}_IMAGEBUILDER_SRC_PIPELINE",
                "Value": event_result['properties']['imagebuilder_source_pipeline_name']
            }
        ]
        
        return self.write_image_tags(image_name, tags_to_write)


    def write_tags_for_event_result(
            self,
            lifecycle_id: str,
            image_name: str, 
            event_result: dict
        ) -> None:

        # handle AMI_BUILD event tagging
        if event_result['name'] == self.constants_service.EVENT_BUILD_AMI:
            return self._write_tags_for_event_ami_build(
                lifecycle_id=lifecycle_id,
                image_name=image_name,
                event_result=event_result
            )


        # handle SMOKE_TESTS CREATE event tagging
        if event_result['name'] == self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE:
            return self._write_tags_for_ami_smoke_tests(
                image_name=image_name,
                event_result=event_result
            )


        # handle VULNERABILITY_SCANS CREATE event tagging
        if event_result['name'] == self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE:
            return self._write_tags_for_ami_vulnerability_scans(
                image_name=image_name,
                event_result=event_result
            )

        # handle QA_CERTIFICATION_REQUEST event tagging
        if event_result['name'] == self.constants_service.EVENT_QA_CERTIFICATION_REQUEST:
            return self._write_tags_for_ami_create_qa_certification_request(
                image_name=image_name,
                event_result=event_result
            )

        # handle QA_CERTIFICATION_RESPONSE event tagging
        if event_result['name'] == self.constants_service.EVENT_QA_CERTIFICATION_RESPONSE:
            return self._write_tags_for_ami_create_qa_certification_response(
                image_name=image_name,
                event_result=event_result
            )

        # handle MARK_FOR_PRODUCTION event tagging
        if event_result['name'] == self.constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE:
            return self._write_tags_for_ami_mark_for_production(
                image_name=image_name,
                event_result=event_result
            )

        # handle AMI_PATCH event tagging
        if event_result['name'] == self.constants_service.EVENT_PATCH_AMI:
            return self._write_tags_for_event_ami_patch(
                image_name=image_name,
                event_result=event_result
            )

        # handle SMOKE_TESTS PATCH event tagging
        if event_result['name'] == self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH:
            return self._write_tags_for_ami_smoke_tests(
                image_name=image_name,
                event_result=event_result
            )


        # handle VULNERABILITY_SCANS PATCH event tagging
        if event_result['name'] == self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_PATCH:
            return self._write_tags_for_ami_vulnerability_scans(
                image_name=image_name,
                event_result=event_result
            )

        # handle MARK_FOR_PRODUCTION event tagging
        if event_result['name'] == self.constants_service.EVENT_MARK_FOR_PRODUCTION_PATCH:
            return self._write_tags_for_ami_mark_for_production(
                image_name=image_name,
                event_result=event_result
            )

    
    def get_ami_details_for_testing(self, definition) -> dict:
        for event in self.lifecycle_service.get_ami_creation_events(definition):
            ami_detail = self.lifecycle_service.get_ami_detail_by_account_id(
                event=event,
                event_name=self.constants_service.EVENT_BUILD_AMI,
                account_id=self.TOOLING_ACCOUNT_ID
            )
            if ami_detail is not None:
                return ami_detail

        raise ValueError(f"Unable to get the detail of the created ami. {json.dumps(definition)}")


    def get_ami_details_for_testing_patch(self, definition) -> list:
        for event in self.lifecycle_service.get_ami_current_patch_events(definition):
            ami_detail = self.lifecycle_service.get_ami_detail_by_account_id(
                event=event,
                event_name=self.constants_service.EVENT_PATCH_AMI,
                account_id=self.TOOLING_ACCOUNT_ID
            )
            if ami_detail is not None:
                return ami_detail

        raise ValueError(f"Unable to get the details of the patched ami. {json.dumps(definition)}")


    def get_base_ami_details_for_patching(self, definition) -> list:
        # check if we have a current patch ami
        for event in self.lifecycle_service.get_ami_current_patch_events(definition):
            ami_detail = self.lifecycle_service.get_ami_detail_by_account_id(
                event=event,
                event_name=self.constants_service.EVENT_PATCH_AMI,
                account_id=self.TOOLING_ACCOUNT_ID
            )
            if ami_detail is not None:
                return ami_detail
                                
        # if there is no current patch ami, return the original created ami
        creation_base_ami_details = self.get_ami_details_for_testing(definition)
        logger.info(f"Patched ancestor base AMI to be used for patching: {json.dumps(creation_base_ami_details)}")
        return creation_base_ami_details

    
    def get_ami_ancestry(self, definition) -> str:
        ami_ancestors = []

        # get original AMI creation id
        ami_ancestors.append(
            {
                "ami_id": self.get_ami_details_for_testing(definition)['image'],
                "ami_semver": self.get_ami_details_for_testing(definition)['ami_semver']
            }
        )

        # get the patched AMI ancestry
        patched_ancestors = self.get_patch_history_sorted_by_date(
            definition=definition, 
            reverse=False
        )

        if patched_ancestors is not None:
            for lifecycle_event in patched_ancestors:
                if lifecycle_event['name'] == self.constants_service.EVENT_PATCH_AMI:
                    for ami_detail in lifecycle_event['properties']['ami_details']:
                        if ami_detail['accountId'] == self.TOOLING_ACCOUNT_ID:
                            ami_ancestors.append(
                                {
                                    "ami_id": ami_detail['image'],
                                    "ami_semver": ami_detail['ami_semver']
                                }
                            )

        ami_ancestors_printable = []
        for ami_ancestor in ami_ancestors:
            ami_ancestors_printable.append(f"{ami_ancestor['ami_id']} (v{ami_ancestor['ami_semver']})")

        msg = (
            "AMI Ancestry for AMI patch operation: " +
            ' -> '.join(ami_ancestors_printable)
        )
        logger.debug(msg) 
        return ' -> '.join(ami_ancestors_printable)


    def get_patch_history_sorted_by_date(self, definition: dict, reverse: bool) -> list:

        patch_ami_events = []
        patched_ancestors = []

        for history in self.lifecycle_service.get_patch_history(definition):
            if 'events' in history:
                for event in history['events']:
                    if event['name'] == self.constants_service.EVENT_PATCH_AMI:
                        patch_ami_events.append(event)

        if len(patch_ami_events) > 0:        
            patched_ancestors = sorted(
                patch_ami_events,
                key=lambda d: datetime.datetime.strptime(d['status_date'], '%m/%d/%Y, %H:%M:%S').replace(tzinfo=datetime.timezone.utc),
                reverse=reverse
            )

            logger.debug("Sorted historical patches by status_date - newset to oldest")
            logger.debug(patched_ancestors)

            return patched_ancestors

        logger.info(
            f"Definition does not contain any historical patch history items." +
            json.dumps(definition, indent=2)
        )
        return None


    def _get_ami_lookup_entry(
            self,
            definition: dict,
            ami_detail: dict,
            lifecycle_type: str,
            lifecycle_event: str
        ) -> dict:
        return {
            "stack_tag": definition['stack_tag'],
            "ami_id": ami_detail['image'],
            "ami_name": ami_detail['name'],
            "ami_semver": ami_detail['ami_semver'],
            "product_ver": definition['product_ver'],
            "product_name": definition['product_name'],
            "commit_ref": definition['commit_ref'],
            "lifecycle_type": lifecycle_type,
            "lifecycle_event": lifecycle_event,
            "aws_region": ami_detail['region'],
            "lifecycle_id": definition['lifecycle_id']
        }


    def _get_ami_lookup_details_creation(
            self, 
            definition: dict,
            lifecycle_type: str,
            lifecycle_event: str
        ) -> list:
        ami_details_list = []
        ami_lookup_list = []
        for event in self.lifecycle_service.get_ami_creation_events(definition):
            ami_detail = self.lifecycle_service.get_ami_detail_by_account_id(
                event=event,
                event_name=self.constants_service.EVENT_BUILD_AMI,
                account_id=self.SHARED_SERVICES_ACCOUNT_ID
            )
            if ami_detail is not None:
                ami_details_list.append(ami_detail)

        if len(ami_details_list) == 0:
            raise ValueError(f"Unable to get the created ami details. {json.dumps(definition)}")
        
        for ami_detail in ami_details_list:
            ami_lookup_list.append(
                self._get_ami_lookup_entry(
                    definition=definition,
                    ami_detail=ami_detail,
                    lifecycle_type=lifecycle_type,
                    lifecycle_event=lifecycle_event
                )
            )

        if len(ami_lookup_list) == 0:
            raise ValueError(f"Unable to generate an ami lookup entry. {json.dumps(definition)}")

        return ami_lookup_list


    def _get_ami_lookup_details_patch(
            self, 
            definition: dict,
            lifecycle_type: str,
            lifecycle_event: str
        ) -> list:
        ami_details_list = []
        ami_lookup_list = []
        for event in self.lifecycle_service.get_ami_current_patch_events(definition):
            ami_detail = self.lifecycle_service.get_ami_detail_by_account_id(
                event=event,
                event_name=self.constants_service.EVENT_PATCH_AMI,
                account_id=self.SHARED_SERVICES_ACCOUNT_ID
            )
            if ami_detail is not None:
                ami_details_list.append(ami_detail)

        if len(ami_details_list) == 0:
            raise ValueError(f"Unable to get the details of the patched ami. {json.dumps(definition)}")
        
        for ami_detail in ami_details_list:
            ami_lookup_list.append(
                self._get_ami_lookup_entry(
                    definition=definition,
                    ami_detail=ami_detail,
                    lifecycle_type=lifecycle_type,
                    lifecycle_event=lifecycle_event
                )
            )

        if len(ami_lookup_list) == 0:
            raise ValueError(f"Unable to generate an ami lookup entry. {json.dumps(definition)}")

        return ami_lookup_list


    def get_ami_lookup_details(
            self, 
            definition: dict,
            lifecycle_type: str,
            lifecycle_event: str,
        ) -> list:

        if lifecycle_type == self.constants_service.AMI_CREATION:
            return self._get_ami_lookup_details_creation(
                definition=definition,
                lifecycle_type=lifecycle_type,
                lifecycle_event=lifecycle_event
            )

        if lifecycle_type == self.constants_service.AMI_PATCH:
            return self._get_ami_lookup_details_patch(
                definition=definition,
                lifecycle_type=lifecycle_type,
                lifecycle_event=lifecycle_event
            )

    def get_latest_ami_semver(
            self,
            definition: dict
        ) -> str:

        # first check if we already have a patched version
        for event in self.lifecycle_service.get_ami_current_patch_events(definition):
            if event['name'] == self.constants_service.EVENT_PATCH_AMI:
                for ami_detail in event['properties']['ami_details']:
                    return ami_detail['ami_semver']

        # we don't have a patch for return the created AMI semver
        for event in self.lifecycle_service.get_ami_creation_events(definition):
            if event['name'] == self.constants_service.EVENT_BUILD_AMI:
                for ami_detail in event['properties']['ami_details']:
                    return ami_detail['ami_semver']

        # no version found so we return default
        return self.DEFAULT_AMI_SEMVER_SEED
