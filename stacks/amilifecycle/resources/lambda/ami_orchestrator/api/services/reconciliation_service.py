#!/usr/bin/env python

"""
    reconciliation_service.py:
    service that verifies that the tags written to the AMI Lifecycle 
    AMIs match the corresponding values in DynamoDB.
    DynamoDB is always the source of truth and the AMI tags
    should reflect the DynamoDB values.
"""

import logging

from benedict import benedict

from ..services.ami_details_service import AmiDetailsService
from ..services.constants_service import ConstantsService
from ..services.database_service import DatabaseService

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

class ReconciliationService:
    """
        Service that verifies that the tags written to the AMI Lifecycle 
        AMIs match the corresponding values in DynamoDB.
        DynamoDB is always the source of truth and the AMI tags
        should reflect the DynamoDB values.
    """

    ami_details_service = AmiDetailsService()
    constants_service = ConstantsService()
    database_service = DatabaseService()

    tag_prefix = constants_service.AMI_LIFECYCLE_TAG_PREFIX

    # events positions
    POSITION_BUILD_AMI = 0
    POSITION_SMOKE_TESTS = 1
    POSITION_VULNERABILITY_SCANS = 2
    POSITION_QA_CERTIFICATION_REQUEST = 3
    POSITION_QA_CERTIFICATION_RESPONSE = 4
    POSITION_MARK_FOR_PRODUCTION_CREATE = 5
    POSITION_PATCH_AMI = 0
    POSITION_MARK_FOR_PRODUCTION_PATCH = 3

    # base key paths
    KP_AMI_CREATION = "outputs_ami_creation"
    KP_AMI_PATCH = "outputs_ami_patch.patch_history.current"

    # common key paths
    KP_LIFECYCLE_ID = 'lifecycle_id'
    KP_PRODUCT_VER = 'product_ver'
    KP_PRODUCT_NAME = 'product_name'

    # create / patch db keys
    KP_CURRENT_PATCH_AMI_NAME = f'{KP_AMI_PATCH}.events[{POSITION_PATCH_AMI}].properties.ami_details[0].name'
    KP_CREATED_AMI_NAME = f'{KP_AMI_CREATION}.events[{POSITION_BUILD_AMI}].properties.ami_details[0].name'
    
    #########################################
    # <START> AMI CREATE DB KEYS
    #########################################

    # event key paths
    KP_BUILD_AMI_EVENT = f'{KP_AMI_CREATION}.events[{POSITION_BUILD_AMI}]'
    KP_SMOKE_TESTS_CREATE_EVENT = f'{KP_AMI_CREATION}.events[{POSITION_SMOKE_TESTS}]'
    KP_VULNERABILITY_SCANS_CREATE_EVENT = f'{KP_AMI_CREATION}.events[{POSITION_VULNERABILITY_SCANS}]'
    KP_QA_CERTIFICATION_REQUEST_EVENT = f'{KP_AMI_CREATION}.events[{POSITION_QA_CERTIFICATION_REQUEST}]'
    KP_QA_CERTIFICATION_RESPONSE_EVENT = f'{KP_AMI_CREATION}.events[{POSITION_QA_CERTIFICATION_RESPONSE}]'
    KP_MARK_FOR_PRODUCTION_CREATE_EVENT = f'{KP_AMI_CREATION}.events[{POSITION_MARK_FOR_PRODUCTION_CREATE}]'

    # build_ami key paths
    KP_BUILD_AMI_EVENT_STATUS = f'{KP_BUILD_AMI_EVENT}.status'
    KP_BUILD_AMI_EVENT_STATUS_DATE = f'{KP_BUILD_AMI_EVENT}.status_date'
    KP_BUILD_AMI_SEMVER = f'{KP_BUILD_AMI_EVENT}.properties.ami_details[0].ami_semver'
    KP_BUILD_AMI_IMAGEBUILDER_ARN = f'{KP_BUILD_AMI_EVENT}.properties.imagebuilder_image_arn'
    KP_BUILD_AMI_IMAGEBUILDER_RECIPE_ARN = f'{KP_BUILD_AMI_EVENT}.properties.imagebuilder_imagerecipe_arn'
    KP_BUILD_AMI_IMAGEBUILDER_RECIPE_NAME = f'{KP_BUILD_AMI_EVENT}.properties.imagebuilder_imagerecipe_name'
    KP_BUILD_AMI_IMAGEBUILDER_PIPELINE_NAME = f'{KP_BUILD_AMI_EVENT}.properties.imagebuilder_source_pipeline_name'
    KP_BUILD_AMI_COMPONENTS = f'{KP_BUILD_AMI_EVENT}.properties.imagebuilder_recipe_components'

    # smoke_tests_create key paths
    KP_SMOKE_TESTS_CREATE_EVENT_STATUS = f'{KP_SMOKE_TESTS_CREATE_EVENT}.status'
    KP_SMOKE_TESTS_CREATE_EVENT_STATUS_DATE = f'{KP_SMOKE_TESTS_CREATE_EVENT}.status_date'

    # vulnerability_scans_create key paths
    KP_VULNERABILITY_SCANS_CREATE_EVENT_STATUS = f'{KP_VULNERABILITY_SCANS_CREATE_EVENT}.status'
    KP_VULNERABILITY_SCANS_CREATE_EVENT_STATUS_DATE = f'{KP_VULNERABILITY_SCANS_CREATE_EVENT}.status_date'
    KP_VULNERABILITY_SCANS_CREATE_EVENT_TOTAL_VULNERABILITIES = f'{KP_VULNERABILITY_SCANS_CREATE_EVENT}.properties.total_vulnerabilities'
    KP_VULNERABILITY_SCANS_CREATE_EVENT_SEVERITIES = f'{KP_VULNERABILITY_SCANS_CREATE_EVENT}.properties.vulnerability_severities'
    KP_VULNERABILITY_SCANS_CREATE_EVENT_S3BUCKET = f'{KP_VULNERABILITY_SCANS_CREATE_EVENT}.properties.vulnerability_scan_report.S3Bucket'
    KP_VULNERABILITY_SCANS_CREATE_EVENT_S3KEY = f'{KP_VULNERABILITY_SCANS_CREATE_EVENT}.properties.vulnerability_scan_report.S3Key'

    # qa_certification_request key paths
    KP_QA_CERTIFICATION_REQUEST_EVENT_STATUS = f'{KP_QA_CERTIFICATION_REQUEST_EVENT}.status'
    KP_QA_CERTIFICATION_REQUEST_EVENT_STATUS_DATE = f'{KP_QA_CERTIFICATION_REQUEST_EVENT}.status_date'
    KP_QA_CERTIFICATION_REQUEST_EVENT_EXPORT_IMAGE_PATH = f'{KP_QA_CERTIFICATION_REQUEST_EVENT}.properties.export_image_path'
    KP_QA_CERTIFICATION_REQUEST_EVENT_EXPORT_IMAGE_ID = f'{KP_QA_CERTIFICATION_REQUEST_EVENT}.properties.export_image_id'
    KP_QA_CERTIFICATION_REQUEST_EVENT_EXPORT_IMAGE_TASK_ID = f'{KP_QA_CERTIFICATION_REQUEST_EVENT}.properties.export_image_task_id'

    # qa_certification_response key paths
    KP_QA_CERTIFICATION_RESPONSE_EVENT_STATUS = f'{KP_QA_CERTIFICATION_RESPONSE_EVENT}.status'
    KP_QA_CERTIFICATION_RESPONSE_EVENT_STATUS_DATE = f'{KP_QA_CERTIFICATION_RESPONSE_EVENT}.status_date'
    KP_QA_CERTIFICATION_RESPONSE_EVENT_CERTIFICATION_STATUS = f'{KP_QA_CERTIFICATION_RESPONSE_EVENT}.certification_status'
    
    # mark_for_production key paths
    KP_MARK_FOR_PRODUCTION_CREATE_EVENT_STATUS = f'{KP_MARK_FOR_PRODUCTION_CREATE_EVENT}.status'
    KP_MARK_FOR_PRODUCTION_CREATE_EVENT_STATUS_DATE = f'{KP_MARK_FOR_PRODUCTION_CREATE_EVENT}.status_date'
    KP_MARK_FOR_PRODUCTION_CREATE_EVENT_APPROVAL_STATUS = f'{KP_MARK_FOR_PRODUCTION_CREATE_EVENT}.approval_status'
    
    #########################################
    # </END> AMI CREATE DB KEYS
    #########################################

    #########################################
    # <START> AMI PATCH DB KEYS
    #########################################

    # event key paths
    KP_PATCH_AMI_EVENT = f'{KP_AMI_PATCH}.events[{POSITION_PATCH_AMI}]'
    KP_SMOKE_TESTS_PATCH_EVENT = f'{KP_AMI_PATCH}.events[{POSITION_SMOKE_TESTS}]'
    KP_VULNERABILITY_SCANS_PATCH_EVENT = f'{KP_AMI_PATCH}.events[{POSITION_VULNERABILITY_SCANS}]'
    KP_MARK_FOR_PRODUCTION_PATCH_EVENT = f'{KP_AMI_PATCH}.events[{POSITION_MARK_FOR_PRODUCTION_PATCH}]'

    # patch_ami key paths
    KP_PATCH_AMI_EVENT_STATUS = f'{KP_PATCH_AMI_EVENT}.status'
    KP_PATCH_AMI_EVENT_STATUS_DATE = f'{KP_PATCH_AMI_EVENT}.status_date'
    KP_PATCH_AMI_SEMVER = f'{KP_PATCH_AMI_EVENT}.properties.ami_details[0].ami_semver'
    KP_PATCH_AMI_IMAGEBUILDER_ARN = f'{KP_PATCH_AMI_EVENT}.properties.imagebuilder_image_arn'
    KP_PATCH_AMI_IMAGEBUILDER_RECIPE_ARN = f'{KP_PATCH_AMI_EVENT}.properties.imagebuilder_imagerecipe_arn'
    KP_PATCH_AMI_IMAGEBUILDER_RECIPE_NAME = f'{KP_PATCH_AMI_EVENT}.properties.imagebuilder_imagerecipe_name'
    KP_PATCH_AMI_IMAGEBUILDER_PIPELINE_NAME = f'{KP_PATCH_AMI_EVENT}.properties.imagebuilder_source_pipeline_name'
    KP_PATCH_AMI_COMPONENTS = f'{KP_PATCH_AMI_EVENT}.properties.imagebuilder_recipe_components'

    # smoke_tests_patch key paths
    KP_SMOKE_TESTS_PATCH_EVENT_STATUS = f'{KP_SMOKE_TESTS_PATCH_EVENT}.status'
    KP_SMOKE_TESTS_PATCH_EVENT_STATUS_DATE = f'{KP_SMOKE_TESTS_PATCH_EVENT}.status_date'

    # vulnerability_scans_patch key paths
    KP_VULNERABILITY_SCANS_PATCH_EVENT_STATUS = f'{KP_VULNERABILITY_SCANS_PATCH_EVENT}.status'
    KP_VULNERABILITY_SCANS_PATCH_EVENT_STATUS_DATE = f'{KP_VULNERABILITY_SCANS_PATCH_EVENT}.status_date'
    KP_VULNERABILITY_SCANS_PATCH_EVENT_TOTAL_VULNERABILITIES = f'{KP_VULNERABILITY_SCANS_PATCH_EVENT}.properties.total_vulnerabilities'
    KP_VULNERABILITY_SCANS_PATCH_EVENT_SEVERITIES = f'{KP_VULNERABILITY_SCANS_PATCH_EVENT}.properties.vulnerability_severities'
    KP_VULNERABILITY_SCANS_PATCH_EVENT_S3BUCKET = f'{KP_VULNERABILITY_SCANS_PATCH_EVENT}.properties.vulnerability_scan_report.S3Bucket'
    KP_VULNERABILITY_SCANS_PATCH_EVENT_S3KEY = f'{KP_VULNERABILITY_SCANS_PATCH_EVENT}.properties.vulnerability_scan_report.S3Key'

    # mark_for_production key paths
    KP_MARK_FOR_PRODUCTION_PATCH_EVENT_STATUS = f'{KP_MARK_FOR_PRODUCTION_PATCH_EVENT}.status'
    KP_MARK_FOR_PRODUCTION_PATCH_EVENT_STATUS_DATE = f'{KP_MARK_FOR_PRODUCTION_PATCH_EVENT}.status_date'
    KP_MARK_FOR_PRODUCTION_PATCH_EVENT_APPROVAL_STATUS = f'{KP_MARK_FOR_PRODUCTION_PATCH_EVENT}.approval_status'
    
    #########################################
    # </END> AMI PATCH DB KEYS
    #########################################


    def _get_db_keys_to_ami_tags_map_by_event_name(
            self, 
            event_name: str,
            definition: benedict,
            event_type: str = None
        ) -> list:
        if event_name == self.constants_service.EVENT_BUILD_AMI:
            return self._map_db_keys_to_ami_tags_for_build_ami(definition)

        if event_name == self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE:
            return self._map_db_keys_to_ami_tags_for_smoke_tests_create(definition)

        if event_name == self.constants_service.EVENT_VULNERABILIY_SCANS_AMI_CREATE:
            return self._map_db_keys_to_ami_tags_for_vulnerability_scans_create(definition)

        if event_name == self.constants_service.EVENT_QA_CERTIFICATION_REQUEST:
            return self._map_db_keys_to_ami_tags_for_qa_certification_request(definition)

        if event_name == self.constants_service.EVENT_QA_CERTIFICATION_RESPONSE:
            return self._map_db_keys_to_ami_tags_for_qa_certification_response(definition)

        if event_name == self.constants_service.EVENT_MARK_FOR_PRODUCTION:
            if event_type == self.constants_service.AMI_CREATION:
                return self._map_db_keys_to_ami_tags_for_mark_for_production_create(definition)

        if event_name == self.constants_service.EVENT_PATCH_AMI:
            return self._map_db_keys_to_ami_tags_for_patch_ami(definition)

        if event_name == self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH:
            return self._map_db_keys_to_ami_tags_for_smoke_tests_patch(definition)

        if event_name == self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_PATCH:
            return self._map_db_keys_to_ami_tags_for_vulnerability_scans_patch(definition)

        if event_name == self.constants_service.EVENT_MARK_FOR_PRODUCTION:
            if event_type == self.constants_service.AMI_PATCH:
                return self._map_db_keys_to_ami_tags_for_mark_for_production_patch(definition)
        
        return None


    #########################################
    # <START> AMI CREATE EVENTS
    #########################################

    def _map_db_keys_to_ami_tags_for_build_ami(
            self, 
            definition: benedict
        ) -> list:
        event = self.constants_service.EVENT_BUILD_AMI
        db_keys_to_ami_tags = []

        # lifecycle_id
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_LIFECYCLE_ID",
                "db_key": self.KP_LIFECYCLE_ID,
                "db_value": definition[self.KP_LIFECYCLE_ID]
            }
        )

        # build_ami status
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS",
                "db_key": self.KP_BUILD_AMI_EVENT_STATUS,
                "db_value": definition[self.KP_BUILD_AMI_EVENT_STATUS]
            }
        )

        # build_ami status date
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS_DATE",
                "db_key": self.KP_BUILD_AMI_EVENT_STATUS_DATE,
                "db_value": definition[self.KP_BUILD_AMI_EVENT_STATUS_DATE]
            }
        )

        # build_ami semver
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_CURRENT_AMI_SEMVER",
                "db_key": self.KP_BUILD_AMI_SEMVER,
                "db_value": definition[self.KP_BUILD_AMI_SEMVER]
            }
        )

        # build_ami product ver
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_PRODUCT_VER",
                "db_key": self.KP_PRODUCT_VER,
                "db_value": definition[self.KP_PRODUCT_VER]
            }
        )

        # build_ami product name
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_PRODUCT_NAME",
                "db_key": self.KP_PRODUCT_NAME,
                "db_value": definition[self.KP_PRODUCT_NAME]
            }
        )

        # build_ami imagebuilder arn
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_IMAGEBUILDER_IMAGE_ARN",
                "db_key": self.KP_BUILD_AMI_IMAGEBUILDER_ARN,
                "db_value": definition[self.KP_BUILD_AMI_IMAGEBUILDER_ARN]
            }
        )

        # build_ami imagebuilder recipe arn
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_IMAGEBUILDER_RECIPE_ARN",
                "db_key": self.KP_BUILD_AMI_IMAGEBUILDER_RECIPE_ARN,
                "db_value": definition[self.KP_BUILD_AMI_IMAGEBUILDER_RECIPE_ARN]
            }
        )

        # build_ami imagebuilder recipe name
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_IMAGEBUILDER_RECIPE_NAME",
                "db_key": self.KP_BUILD_AMI_IMAGEBUILDER_RECIPE_NAME,
                "db_value": definition[self.KP_BUILD_AMI_IMAGEBUILDER_RECIPE_NAME]
            }
        )

        # build_ami imagebuilder recipe name
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_IMAGEBUILDER_SRC_PIPELINE",
                "db_key": self.KP_BUILD_AMI_IMAGEBUILDER_PIPELINE_NAME,
                "db_value": definition[self.KP_BUILD_AMI_IMAGEBUILDER_PIPELINE_NAME]
            }
        )

        # build_ami components
        components = []
        if self.KP_BUILD_AMI_COMPONENTS in definition:
            for component in definition[self.KP_BUILD_AMI_COMPONENTS]:
                # grab the component name and add to list
                components.append(component['componentArn'].partition("component/")[2])

            db_keys_to_ami_tags.append(
                {
                    "ami_tag": f"{self.tag_prefix}_COMPONENTS",
                    "db_key": self.KP_BUILD_AMI_COMPONENTS,
                    "db_value": ",".join(components)
                }
            )
        else:
            raise ValueError(f"DB Key:{self.KP_BUILD_AMI_COMPONENTS} not found for lifecycle: {definition['lifecycle_id']}")

        return db_keys_to_ami_tags


    def _map_db_keys_to_ami_tags_for_smoke_tests_create(
            self, 
            definition: benedict
        ) -> list:
        event = self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE
        db_keys_to_ami_tags = []

        # smoke_tests_create status
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS",
                "db_key": self.KP_SMOKE_TESTS_CREATE_EVENT_STATUS,
                "db_value": definition[self.KP_SMOKE_TESTS_CREATE_EVENT_STATUS]
            }
        )

        # smoke_tests_create status date
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS_DATE",
                "db_key": self.KP_SMOKE_TESTS_CREATE_EVENT_STATUS_DATE,
                "db_value": definition[self.KP_SMOKE_TESTS_CREATE_EVENT_STATUS_DATE]
            }
        )

        return db_keys_to_ami_tags


    def _map_db_keys_to_ami_tags_for_vulnerability_scans_create(
            self, 
            definition: benedict
        ) -> list:
        event = self.constants_service.EVENT_VULNERABILIY_SCANS_AMI_CREATE
        db_keys_to_ami_tags = []

        # vulnerability_scans_create status
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS",
                "db_key": self.KP_VULNERABILITY_SCANS_CREATE_EVENT_STATUS,
                "db_value": definition[self.KP_VULNERABILITY_SCANS_CREATE_EVENT_STATUS]
            }
        )

        # vulnerability_scans_create status date
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS_DATE",
                "db_key": self.KP_VULNERABILITY_SCANS_CREATE_EVENT_STATUS_DATE,
                "db_value": definition[self.KP_VULNERABILITY_SCANS_CREATE_EVENT_STATUS_DATE]
            }
        )

        # vulnerability_scans_create total vulnerabilities
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_TOTAL_VULNERABILITIES",
                "db_key": self.KP_VULNERABILITY_SCANS_CREATE_EVENT_TOTAL_VULNERABILITIES,
                "db_value": definition[self.KP_VULNERABILITY_SCANS_CREATE_EVENT_TOTAL_VULNERABILITIES]
            }
        )

        # vulnerability_scans_create severities
        if self.KP_VULNERABILITY_SCANS_CREATE_EVENT_SEVERITIES in definition:
            severities = definition[self.KP_VULNERABILITY_SCANS_CREATE_EVENT_SEVERITIES]
            vulnerability_severities = (
                f"CRITICAL: {severities['CRITICAL']}, HIGH: {severities['HIGH']}, " +
                f"MEDIUM: {severities['MEDIUM']}, LOW: {severities['LOW']}, " +
                f"INFORMATIONAL: {severities['INFORMATIONAL']}, UNTRIAGED: {severities['UNTRIAGED']}"
            )

            db_keys_to_ami_tags.append(
                {
                    "ami_tag": f"{self.tag_prefix}_EVENT_{event}_SEVERITIES",
                    "db_key": self.KP_VULNERABILITY_SCANS_CREATE_EVENT_SEVERITIES,
                    "db_value": vulnerability_severities
                }
            )
        else:
            raise ValueError(f"DB Key:{self.KP_VULNERABILITY_SCANS_CREATE_EVENT_SEVERITIES} not found for lifecycle: {definition['lifecycle_id']}")

        # vulnerability_scans_create scan report
        if (
            self.KP_VULNERABILITY_SCANS_CREATE_EVENT_S3BUCKET in definition 
            and self.KP_VULNERABILITY_SCANS_CREATE_EVENT_S3KEY in definition
        ):
            vulnerability_scan_report = (
                f"s3://{definition[self.KP_VULNERABILITY_SCANS_CREATE_EVENT_S3BUCKET]}/" +
                definition[self.KP_VULNERABILITY_SCANS_CREATE_EVENT_S3KEY]
            )
            db_keys_to_ami_tags.append(
                {
                    "ami_tag": f"{self.tag_prefix}_EVENT_{event}_SCAN_REPORT",
                    "db_key": self.KP_VULNERABILITY_SCANS_CREATE_EVENT_S3BUCKET,
                    "db_value": vulnerability_scan_report
                }
            )
        else:
            raise ValueError(f"DB Key:{self.KP_VULNERABILITY_SCANS_CREATE_EVENT_S3BUCKET} not found for lifecycle: {definition['lifecycle_id']}")

        return db_keys_to_ami_tags


    def _map_db_keys_to_ami_tags_for_qa_certification_request(
            self, 
            definition: benedict
        ) -> list:
        event = self.constants_service.EVENT_QA_CERTIFICATION_REQUEST
        db_keys_to_ami_tags = []

        # qa_certification_request status
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS",
                "db_key": self.KP_QA_CERTIFICATION_REQUEST_EVENT_STATUS,
                "db_value": definition[self.KP_QA_CERTIFICATION_REQUEST_EVENT_STATUS]
            }
        )

        # qa_certification_request status date
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS_DATE",
                "db_key": self.KP_QA_CERTIFICATION_REQUEST_EVENT_STATUS_DATE,
                "db_value": definition[self.KP_QA_CERTIFICATION_REQUEST_EVENT_STATUS_DATE]
            }
        )

        # qa_certification_request export image path
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_EXPORT_IMAGE_PATH",
                "db_key": self.KP_QA_CERTIFICATION_REQUEST_EVENT_EXPORT_IMAGE_PATH,
                "db_value": definition[self.KP_QA_CERTIFICATION_REQUEST_EVENT_EXPORT_IMAGE_PATH]
            }
        )

        # qa_certification_request export image id
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_EXPORT_IMAGE_ID",
                "db_key": self.KP_QA_CERTIFICATION_REQUEST_EVENT_EXPORT_IMAGE_ID,
                "db_value": definition[self.KP_QA_CERTIFICATION_REQUEST_EVENT_EXPORT_IMAGE_ID]
            }
        )

        # qa_certification_request export image task id
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_EXPORT_IMAGE_TASK_ID",
                "db_key": self.KP_QA_CERTIFICATION_REQUEST_EVENT_EXPORT_IMAGE_TASK_ID,
                "db_value": definition[self.KP_QA_CERTIFICATION_REQUEST_EVENT_EXPORT_IMAGE_TASK_ID]
            }
        )

        return db_keys_to_ami_tags


    def _map_db_keys_to_ami_tags_for_qa_certification_response(
            self, 
            definition: benedict
        ) -> list:
        event = self.constants_service.EVENT_QA_CERTIFICATION_RESPONSE
        db_keys_to_ami_tags = []

        # qa_certification_response status
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS",
                "db_key": self.KP_QA_CERTIFICATION_RESPONSE_EVENT_STATUS,
                "db_value": definition[self.KP_QA_CERTIFICATION_RESPONSE_EVENT_STATUS]
            }
        )

        # qa_certification_response status date
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS_DATE",
                "db_key": self.KP_QA_CERTIFICATION_RESPONSE_EVENT_STATUS_DATE,
                "db_value": definition[self.KP_QA_CERTIFICATION_RESPONSE_EVENT_STATUS_DATE]
            }
        )

        # qa_certification_response certification status
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_QA_CERTIFICATION_STATUS",
                "db_key": self.KP_QA_CERTIFICATION_RESPONSE_EVENT_CERTIFICATION_STATUS,
                "db_value": definition[self.KP_QA_CERTIFICATION_RESPONSE_EVENT_CERTIFICATION_STATUS]
            }
        )

        return db_keys_to_ami_tags


    def _map_db_keys_to_ami_tags_for_mark_for_production_create(
            self, 
            definition: benedict
        ) -> list:
        event = self.constants_service.EVENT_MARK_FOR_PRODUCTION
        db_keys_to_ami_tags = []

        # mark_for_production status
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS",
                "db_key": self.KP_MARK_FOR_PRODUCTION_CREATE_EVENT_STATUS,
                "db_value": definition[self.KP_MARK_FOR_PRODUCTION_CREATE_EVENT_STATUS]
            }
        )

        # mark_for_production status date
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS_DATE",
                "db_key": self.KP_MARK_FOR_PRODUCTION_CREATE_EVENT_STATUS_DATE,
                "db_value": definition[self.KP_MARK_FOR_PRODUCTION_CREATE_EVENT_STATUS_DATE]
            }
        )

        # mark_for_production certification status
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_APPROVAL_STATUS",
                "db_key": self.KP_MARK_FOR_PRODUCTION_CREATE_EVENT_APPROVAL_STATUS,
                "db_value": definition[self.KP_MARK_FOR_PRODUCTION_CREATE_EVENT_APPROVAL_STATUS]
            }
        )

        return db_keys_to_ami_tags

    #########################################
    # </END> AMI CREATE EVENTS
    #########################################


    #########################################
    # <START> AMI PATCH EVENTS
    #########################################

    def _map_db_keys_to_ami_tags_for_patch_ami(
            self, 
            definition: benedict
        ) -> list:
        event = self.constants_service.EVENT_PATCH_AMI
        db_keys_to_ami_tags = []

        # lifecycle_id
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_LIFECYCLE_ID",
                "db_key": self.KP_LIFECYCLE_ID,
                "db_value": definition[self.KP_LIFECYCLE_ID]
            }
        )

        # patch_ami status
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS",
                "db_key": self.KP_PATCH_AMI_EVENT_STATUS,
                "db_value": definition[self.KP_PATCH_AMI_EVENT_STATUS]
            }
        )

        # patch_ami status date
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS_DATE",
                "db_key": self.KP_BUILD_AMI_EVENT_STATUS_DATE,
                "db_value": definition[self.KP_PATCH_AMI_EVENT_STATUS_DATE]
            }
        )

        # patch_ami semver
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_CURRENT_AMI_SEMVER",
                "db_key": self.KP_PATCH_AMI_SEMVER,
                "db_value": definition[self.KP_PATCH_AMI_SEMVER]
            }
        )

        # patch_ami product version
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_PRODUCT_VER",
                "db_key": self.KP_PRODUCT_VER,
                "db_value": definition[self.KP_PRODUCT_VER]
            }
        )

        # patch_ami product name
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_PRODUCT_NAME",
                "db_key": self.KP_PRODUCT_NAME,
                "db_value": definition[self.KP_PRODUCT_NAME]
            }
        )

        # patch_ami imagebuilder arn
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_IMAGEBUILDER_IMAGE_ARN",
                "db_key": self.KP_PATCH_AMI_IMAGEBUILDER_ARN,
                "db_value": definition[self.KP_PATCH_AMI_IMAGEBUILDER_ARN]
            }
        )

        # patch_ami imagebuilder recipe arn
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_IMAGEBUILDER_RECIPE_ARN",
                "db_key": self.KP_PATCH_AMI_IMAGEBUILDER_RECIPE_ARN,
                "db_value": definition[self.KP_PATCH_AMI_IMAGEBUILDER_RECIPE_ARN]
            }
        )

        # patch_ami imagebuilder recipe name
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_IMAGEBUILDER_RECIPE_NAME",
                "db_key": self.KP_PATCH_AMI_IMAGEBUILDER_RECIPE_NAME,
                "db_value": definition[self.KP_PATCH_AMI_IMAGEBUILDER_RECIPE_NAME]
            }
        )

        # patch_ami imagebuilder recipe name
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_IMAGEBUILDER_SRC_PIPELINE",
                "db_key": self.KP_PATCH_AMI_IMAGEBUILDER_PIPELINE_NAME,
                "db_value": definition[self.KP_PATCH_AMI_IMAGEBUILDER_PIPELINE_NAME]
            }
        )

        # patch_ami components
        components = []
        if self.KP_PATCH_AMI_COMPONENTS in definition:
            for component in definition[self.KP_PATCH_AMI_COMPONENTS]:
                # grab the component name and add to list
                components.append(component['componentArn'].partition("component/")[2])

            db_keys_to_ami_tags.append(
                {
                    "ami_tag": f"{self.tag_prefix}_COMPONENTS",
                    "db_key": self.KP_PATCH_AMI_COMPONENTS,
                    "db_value": ",".join(components)
                }
            )
        else:
            raise ValueError(f"DB Key:{self.KP_PATCH_AMI_COMPONENTS} not found for lifecycle: {definition['lifecycle_id']}")

        return db_keys_to_ami_tags


    def _map_db_keys_to_ami_tags_for_smoke_tests_patch(
            self, 
            definition: benedict
        ) -> list:
        event = self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH
        db_keys_to_ami_tags = []

        # smoke_tests_patch status
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS",
                "db_key": self.KP_SMOKE_TESTS_PATCH_EVENT_STATUS,
                "db_value": definition[self.KP_SMOKE_TESTS_PATCH_EVENT_STATUS]
            }
        )

        # smoke_tests_patch status date
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS_DATE",
                "db_key": self.KP_SMOKE_TESTS_PATCH_EVENT_STATUS_DATE,
                "db_value": definition[self.KP_SMOKE_TESTS_PATCH_EVENT_STATUS_DATE]
            }
        )

        return db_keys_to_ami_tags


    def _map_db_keys_to_ami_tags_for_vulnerability_scans_patch(
            self, 
            definition: benedict
        ) -> list:
        event = self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_PATCH
        db_keys_to_ami_tags = []

        # vulnerability_scans_patch status
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS",
                "db_key": self.KP_VULNERABILITY_SCANS_PATCH_EVENT_STATUS,
                "db_value": definition[self.KP_VULNERABILITY_SCANS_PATCH_EVENT_STATUS]
            }
        )

        # vulnerability_scans_patch status date
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS_DATE",
                "db_key": self.KP_VULNERABILITY_SCANS_PATCH_EVENT_STATUS_DATE,
                "db_value": definition[self.KP_VULNERABILITY_SCANS_PATCH_EVENT_STATUS_DATE]
            }
        )

        # vulnerability_scans_patch total vulnerabilities
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_TOTAL_VULNERABILITIES",
                "db_key": self.KP_VULNERABILITY_SCANS_PATCH_EVENT_TOTAL_VULNERABILITIES,
                "db_value": definition[self.KP_VULNERABILITY_SCANS_PATCH_EVENT_TOTAL_VULNERABILITIES]
            }
        )

        # vulnerability_scans_patch severities
        if self.KP_VULNERABILITY_SCANS_PATCH_EVENT_SEVERITIES in definition:
            severities = definition[self.KP_VULNERABILITY_SCANS_PATCH_EVENT_SEVERITIES]
            vulnerability_severities = (
                f"CRITICAL: {severities['CRITICAL']}, HIGH: {severities['HIGH']}, " +
                f"MEDIUM: {severities['MEDIUM']}, LOW: {severities['LOW']}, " +
                f"INFORMATIONAL: {severities['INFORMATIONAL']}, UNTRIAGED: {severities['UNTRIAGED']}"
            )

            db_keys_to_ami_tags.append(
                {
                    "ami_tag": f"{self.tag_prefix}_EVENT_{event}_SEVERITIES",
                    "db_key": self.KP_VULNERABILITY_SCANS_PATCH_EVENT_SEVERITIES,
                    "db_value": vulnerability_severities
                }
            )
        else:
            raise ValueError(f"DB Key:{self.KP_VULNERABILITY_SCANS_PATCH_EVENT_SEVERITIES} not found for lifecycle: {definition['lifecycle_id']}")

        # vulnerability_scans_patch scan report
        if (
            self.KP_VULNERABILITY_SCANS_PATCH_EVENT_S3BUCKET in definition 
            and self.KP_VULNERABILITY_SCANS_PATCH_EVENT_S3KEY in definition
        ):
            vulnerability_scan_report = (
                f"s3://{definition[self.KP_VULNERABILITY_SCANS_PATCH_EVENT_S3BUCKET]}/" +
                definition[self.KP_VULNERABILITY_SCANS_PATCH_EVENT_S3KEY]
            )
            db_keys_to_ami_tags.append(
                {
                    "ami_tag": f"{self.tag_prefix}_EVENT_{event}_SCAN_REPORT",
                    "db_key": self.KP_VULNERABILITY_SCANS_PATCH_EVENT_S3BUCKET,
                    "db_value": vulnerability_scan_report
                }
            )
        else:
            raise ValueError(f"DB Key:{self.KP_VULNERABILITY_SCANS_PATCH_EVENT_S3BUCKET} not found for lifecycle: {definition['lifecycle_id']}")

        return db_keys_to_ami_tags

    def _map_db_keys_to_ami_tags_for_mark_for_production_patch(
            self, 
            definition: benedict
        ) -> list:
        event = self.constants_service.EVENT_MARK_FOR_PRODUCTION
        db_keys_to_ami_tags = []

        # mark_for_production status
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS",
                "db_key": self.KP_MARK_FOR_PRODUCTION_PATCH_EVENT_STATUS,
                "db_value": definition[self.KP_MARK_FOR_PRODUCTION_PATCH_EVENT_STATUS]
            }
        )

        # mark_for_production status date
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_STATUS_DATE",
                "db_key": self.KP_MARK_FOR_PRODUCTION_PATCH_EVENT_STATUS_DATE,
                "db_value": definition[self.KP_MARK_FOR_PRODUCTION_PATCH_EVENT_STATUS_DATE]
            }
        )

        # mark_for_production certification status
        db_keys_to_ami_tags.append(
            {
                "ami_tag": f"{self.tag_prefix}_EVENT_{event}_APPROVAL_STATUS",
                "db_key": self.KP_MARK_FOR_PRODUCTION_PATCH_EVENT_APPROVAL_STATUS,
                "db_value": definition[self.KP_MARK_FOR_PRODUCTION_PATCH_EVENT_APPROVAL_STATUS]
            }
        )

        return db_keys_to_ami_tags

    #########################################
    # </END> AMI PATCH EVENTS
    #########################################


    def get_db_keys_to_ami_tags(self, deployment_lifecycle: dict) -> list:
        
        # cast dict to benedict to enable keypath access to dict items
        definition = benedict(deployment_lifecycle)

        reconcile_obj = {}
        reconcile_obj['events'] = []

        # check which events the lifecycle has

        # patches take precendence over creations
        # if we have a patched AMI then reconcile the patch details
        #########################################
        # PATCHED AMI
        #########################################
        if self.KP_PATCH_AMI_EVENT in definition:

            if self.KP_PATCH_AMI_EVENT in definition:
                reconcile_obj['events'].extend(
                    self._get_db_keys_to_ami_tags_map_by_event_name(
                        event_name=self.constants_service.EVENT_PATCH_AMI,
                        definition=definition
                    )
                )

            if self.KP_SMOKE_TESTS_PATCH_EVENT in definition:
                reconcile_obj['events'].extend(
                    self._get_db_keys_to_ami_tags_map_by_event_name(
                        event_name=self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH,
                        definition=definition
                    )
                )

            if self.KP_VULNERABILITY_SCANS_PATCH_EVENT in definition:
                reconcile_obj['events'].extend(
                    self._get_db_keys_to_ami_tags_map_by_event_name(
                        event_name=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_PATCH,
                        definition=definition
                    )
                )

            if self.KP_MARK_FOR_PRODUCTION_PATCH_EVENT in definition:
                reconcile_obj['events'].extend(
                    self._get_db_keys_to_ami_tags_map_by_event_name(
                        event_name=self.constants_service.EVENT_MARK_FOR_PRODUCTION,
                        definition=definition,
                        event_type=self.constants_service.AMI_PATCH
                    )
                )

            if self.KP_CURRENT_PATCH_AMI_NAME in definition:
                reconcile_obj["ami_name"] = definition[self.KP_CURRENT_PATCH_AMI_NAME]

            if (
                reconcile_obj is None 
                or "ami_name" not in reconcile_obj
                or reconcile_obj["ami_name"] is None
            ):
                logger.error(f"No valid AMI details found for: {definition}")
                raise ValueError(f"No valid AMI details found for: {definition}")
            
            return reconcile_obj

        #########################################
        # CREATED AMI
        #########################################
        # if we do not have a patched AMI then reconcile the created details
        if self.KP_BUILD_AMI_EVENT in definition:

            if self.KP_BUILD_AMI_EVENT in definition:
                reconcile_obj['events'].extend(
                    self._get_db_keys_to_ami_tags_map_by_event_name(
                        event_name=self.constants_service.EVENT_BUILD_AMI,
                        definition=definition
                    )
                )
  
            if self.KP_SMOKE_TESTS_CREATE_EVENT in definition:
                reconcile_obj['events'].extend(
                    self._get_db_keys_to_ami_tags_map_by_event_name(
                        event_name=self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE,
                        definition=definition
                    )
                )

            if self.KP_VULNERABILITY_SCANS_CREATE_EVENT in definition:
                reconcile_obj['events'].extend(
                    self._get_db_keys_to_ami_tags_map_by_event_name(
                        event_name=self.constants_service.EVENT_VULNERABILIY_SCANS_AMI_CREATE,
                        definition=definition
                    )
                )

            if self.KP_QA_CERTIFICATION_REQUEST_EVENT in definition:
                reconcile_obj['events'].extend(
                    self._get_db_keys_to_ami_tags_map_by_event_name(
                        event_name=self.constants_service.EVENT_QA_CERTIFICATION_REQUEST,
                        definition=definition
                    )
                )

            if self.KP_QA_CERTIFICATION_RESPONSE_EVENT in definition:
                reconcile_obj['events'].extend(
                    self._get_db_keys_to_ami_tags_map_by_event_name(
                        event_name=self.constants_service.EVENT_QA_CERTIFICATION_RESPONSE,
                        definition=definition
                    )
                )

            if self.KP_MARK_FOR_PRODUCTION_CREATE_EVENT in definition:
                reconcile_obj['events'].extend(
                    self._get_db_keys_to_ami_tags_map_by_event_name(
                        event_name=self.constants_service.EVENT_MARK_FOR_PRODUCTION,
                        definition=definition,
                        event_type=self.constants_service.AMI_CREATION
                    )
                )

            if self.KP_CREATED_AMI_NAME in definition:
                reconcile_obj["ami_name"] = definition[self.KP_CREATED_AMI_NAME]

            if (
                reconcile_obj is None 
                or "ami_name" not in reconcile_obj
                or reconcile_obj["ami_name"] is None
            ):
                logger.error(f"No valid AMI details found for: {definition}")
                raise ValueError(f"No valid AMI details found for: {definition}")
            
            return reconcile_obj


    def get_ami_tags(self, image_name: str) -> list:
        return self.ami_details_service.get_ami_tags(image_name)

    
    def reconcile_db_keys_to_tags(
            self,
            lifecycle_id: str,
            db_keys_to_ami_tags_map: dict,
            ami_tag_details: list
        ) -> dict:

        error_report = {}
        error_report['lifecycle_id'] = lifecycle_id
        error_report['error_missing_tag_keys'] = []
        error_report['error_missing_tag_values'] = []

        for reconcile_obj in db_keys_to_ami_tags_map.get('events', []):
            expected_tag_key = reconcile_obj["ami_tag"]
            expected_tag_value = reconcile_obj["db_value"][:255]

            
            for ami_tag_detail in ami_tag_details:
                ami_id = ami_tag_detail["ami_id"]
                ami_tags = ami_tag_detail["ami_tags"]
                ami_details = ami_tag_detail["ami_details"]
                ami_tag_keys = [ami_tag['Key'] for ami_tag in ami_tags]
                
                # check if tag exists
                if expected_tag_key not in ami_tag_keys:
                    error_report['error_missing_tag_keys'].append(
                        {
                            "ami_id": ami_id,
                            "ami_account_id": ami_details['ownerId'],
                            "ami_region": ami_details['ami_region'],
                            "ami_location": ami_details['ami_location'],
                            "ami_name": ami_details['ami_location'].rsplit("/", 1)[1],
                            "missing_tag": expected_tag_key,
                            "expected_tag_value": expected_tag_value
                        }
                    )
                
                # check if tag value matches db value
                for ami_tag in ami_tags:
                    if ami_tag['Key'] == expected_tag_key:
                        if ami_tag['Value'] != expected_tag_value:
                            error_report['error_missing_tag_values'].append(
                                {
                                    "ami_id": ami_id,
                                    "ami_account_id": ami_details['ownerId'],
                                    "ami_region": ami_details['ami_region'],
                                    "ami_location": ami_details['ami_location'],
                                    "ami_name": ami_details['ami_location'].rsplit("/", 1)[1],
                                    "tag_key": expected_tag_key,
                                    "expected_tag_value": expected_tag_value,
                                    "actual_tag_value": ami_tag['Value']
                                }
                            )

        if (
            len(error_report['error_missing_tag_keys']) > 0
            or len(error_report['error_missing_tag_values']) > 0
        ):
            return error_report

        return None


    def repair_missing_tags(self, image_name: str, tags_to_write):
        self.ami_details_service.write_image_tags(image_name, tags_to_write)
