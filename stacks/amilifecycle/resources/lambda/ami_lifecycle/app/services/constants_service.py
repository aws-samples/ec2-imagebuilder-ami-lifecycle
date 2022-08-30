#!/usr/bin/env python

"""
    constants_service.py:
    service which provides project wide static constants.
"""

import logging

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

class ConstantsService:

    # API type
    AMI_CREATION = "ami-creation"
    AMI_PATCH = "ami-patch"
    
    # Event definiitons -- CREATE
    EVENT_BUILD_AMI = "BUILD_AMI"
    EVENT_SMOKE_TESTS_AMI_CREATE = "SMOKE_TESTS_AMI_CREATE"
    EVENT_VULNERABILITY_SCANS_AMI_CREATE = "VULNERABILIY_SCANS_AMI_CREATE"
    EVENT_QA_CERTIFICATION_REQUEST = "QA_CERTIFICATION_REQUEST"
    EVENT_MARK_FOR_PRODUCTION_CREATE = "MARK_FOR_PRODUCTION_CREATE"

      # Event definiitons -- PATCH
    EVENT_PATCH_AMI = "PATCH_AMI"
    EVENT_SMOKE_TESTS_AMI_PATCH = "SMOKE_TESTS_AMI_PATCH"
    EVENT_VULNERABILITY_SCANS_AMI_PATCH = "VULNERABILITY_SCANS_AMI_PATCH"
    EVENT_MARK_FOR_PRODUCTION_PATCH = "MARK_FOR_PRODUCTION_PATCH"

    # callback events
    EVENT_QA_CERTIFICATION_RESPONSE = "QA_CERTIFICATION_RESPONSE"

    LIFECYCLE_EVENTS = [
        EVENT_BUILD_AMI,
        EVENT_SMOKE_TESTS_AMI_CREATE,
        EVENT_VULNERABILITY_SCANS_AMI_CREATE,
        EVENT_QA_CERTIFICATION_REQUEST
    ]

    LIFECYCLE_PATCH_EVENTS = [
        EVENT_PATCH_AMI,
        EVENT_SMOKE_TESTS_AMI_PATCH,
        EVENT_VULNERABILITY_SCANS_AMI_PATCH
    ]

    # event descriptions -- CREATE
    EVENT_BUILD_AMI_DESCRIPTION = "Build an AMI via the EC2 ImageBuilder pipeline using an ImageRecipe and installation components."
    EVENT_SMOKE_TESTS_AMI_CREATE_DESCRIPTION = "Executes a series of smoke tests against a new AMI."
    EVENT_VULNERABILITY_SCANS_AMI_CREATE_DESCRIPTION = "Executes a series of vulnerability scans against a new AMI."
    EVENT_QA_CERTIFICATION_REQUEST_DESCRIPTION = "Exports an AMI to VMDK format. Requests application certification from an external QA team."
    EVENT_QA_CERTIFICATION_RESPONSE_DESCRIPTION = "Receives result of external QA team application certification process."
    EVENT_MARK_FOR_PRODUCTION_CREATE_DESCRIPTION = (
        "Notification approving a new AMI for use in a production environment. " +
        "The AMI is backed up to an S3 Bucket as part of this event"
    )

    
    # event descriptions -- CREATE
    EVENT_PATCH_AMI_DESCRIPTION = "Patch an existing AMI via the EC2 ImageBuilder pipeline using an ImageRecipe and a patch component."
    EVENT_SMOKE_TESTS_AMI_PATCH_DESCRIPTION = "Executes a series of smoke tests against a patched AMI."
    EVENT_VULNERABILITY_SCANS_AMI_PATCH_DESCRIPTION = "Executes a series of vulnerability scans against a patched AMI."
    EVENT_MARK_FOR_PRODUCTION_PATCH_DESCRIPTION = (
        "Notification approving a patched AMI for use in a production environment. " +
        "The AMI is backed up to an S3 Bucket as part of this event"
    )

    # status definitions
    STATUS_COMPLETED = "COMPLETED"
    STATUS_NOT_STARTED = "NOT_STARTED"
    STATUS_FAILED = "FAILED"
    STATUS_IN_PROGRESS = "IN_PROGRESS"
    STATUS_ERROR = "ERROR"
    STATUS_ERROR_EVENT_TIMEOUT = "ERROR_EVENT_TIMEOUT"

    VALID_STATUSES = [
        STATUS_COMPLETED,
        STATUS_FAILED,
        STATUS_IN_PROGRESS,
        STATUS_ERROR,
        STATUS_ERROR_EVENT_TIMEOUT
    ]

    # AMI Tagging
    AMI_LIFECYCLE_TAG_PREFIX = "AMI_LC"

    # AMI Sequence
    AMI_CREATION_SEQ = [
        EVENT_BUILD_AMI,
        EVENT_SMOKE_TESTS_AMI_CREATE,
        EVENT_VULNERABILITY_SCANS_AMI_CREATE,
        EVENT_QA_CERTIFICATION_REQUEST,
        EVENT_QA_CERTIFICATION_RESPONSE,
        EVENT_MARK_FOR_PRODUCTION_CREATE

    ]
    
    AMI_PATCH_SEQ = [
        EVENT_PATCH_AMI,
        EVENT_SMOKE_TESTS_AMI_PATCH,
        EVENT_VULNERABILITY_SCANS_AMI_PATCH,
        EVENT_MARK_FOR_PRODUCTION_PATCH
    ]

    # CLOUDFORMATION_STACKS
    CLOUDFORMATION_STACK_IMAGEBULDER = "IMAGE_BUILDER"
    CLOUDFORMATION_STACK_AMI_LIFECYCLE = "AMI_LIFECYCLE"