#!/usr/bin/env python

"""
    validator_service.py:
    service that validates the input payloads for the
    AMI Orchestrator API.
"""

import logging

from .constants_service import ConstantsService
from .rules_service import RulesService

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class ValidatorService:
    """ 
        Service that validates the input payloads for the
        AMI Orchestrator API.
    """

    constants_service = ConstantsService()
    rules_service = RulesService()

    def get_service_name(self) -> str:
        return "validator service"


    def _validate_common_create_update_request(self, definition) -> None: 
       # validate stack tag
        if 'stack_tag' not in definition:
            raise ValueError("The stack_tag parameter must be defined as part of a lifecycle creation/update request.")

        # validate owner 
        if 'owner' not in definition:
            raise ValueError("The owner parameter must be defined as part of a lifecycle creation/update request.")

        # validate notification
        if 'notifications' not in definition:
            raise ValueError("The notifications parameter must be defined as part of a lifecycle creation/update request.")

        # validate notifications length
        if len(definition['notifications']) == 0:
            raise ValueError("The notifications parameter must contain at least one target type as part of a lifecycle creation/update request.")

        # validate events
        if 'events' not in definition:
            raise ValueError("The events parameter must be defined as part of a lifecycle creation/update request.")

        # validate notifications length
        if len(definition['events']) != len(self.constants_service.LIFECYCLE_EVENTS):
            raise ValueError(f"The events parameter must contain the all {len(self.constants_service.LIFECYCLE_EVENTS)} event definitions as part of a lifecycle creation/update request.")

        # validate event generic
        for event in definition['events']:

            # generic validation
            if 'name' not in event:
                raise ValueError("The name parameter must be defined for an event as part of a lifecycle creation/update request.")
            
            if event['name'].upper() not in self.constants_service.LIFECYCLE_EVENTS:
                raise ValueError(f"The name parameter {event['name']} is not valid. It must be one of {','.join(self.constants_service.LIFECYCLE_EVENTS)}.")

            if 'enabled' not in event:
                raise ValueError("The enabled parameter must be defined for an event as part of a lifecycle creation/update request.")

        # validate event logic
        event_details = {}
        for event in definition['events']:
            event_details[event['name']] = event['enabled']

        # check if logic step jumped
        if event_details[self.constants_service.EVENT_QA_CERTIFICATION_REQUEST] == True:
            if event_details[self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE] == True:
                if event_details[self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE] == False:
                    self.rules_service.raise_error_failed_prerequisites(
                        current_event=self.constants_service.EVENT_QA_CERTIFICATION_REQUEST,
                        previous_event=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE,
                        previous_event_status="False"
                    )

        if event_details[self.constants_service.EVENT_BUILD_AMI] == True:
            if event_details[self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE] == True or event_details[self.constants_service.EVENT_QA_CERTIFICATION_REQUEST] == True:
                if event_details[self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE] == False:
                    self.rules_service.raise_error_failed_prerequisites(
                        current_event=self.constants_service.EVENT_BUILD_AMI,
                        previous_event=self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE,
                        previous_event_status="False"
                    )


    def _validate_common_patch_update_request(self, definition) -> None:
        # validate lifecycle id
        if 'lifecycle_id' not in definition:
            raise ValueError("The lifecycle_id parameter must be defined as part of a lifecycle patch/update request.")

        # validate stack tag
        if 'stack_tag' not in definition:
            raise ValueError("The stack_tag parameter must be defined as part of a lifecycle patch/update request.")

        # validate owner 
        if 'owner' not in definition:
            raise ValueError("The owner parameter must be defined as part of a lifecycle patch/update request.")

        # validate notification
        if 'notifications' not in definition:
            raise ValueError("The notifications parameter must be defined as part of a lifecycle patch/update request.")

        # validate notifications length
        if len(definition['notifications']) == 0:
            raise ValueError("The notifications parameter must contain at least one target type as part of a lifecycle patch/update request.")

        # validate events
        if 'events' not in definition:
            raise ValueError("The events parameter must be defined as part of a lifecycle patch/update request.")

        # validate notifications length
        if len(definition['events']) != len(self.constants_service.LIFECYCLE_PATCH_EVENTS):
            raise ValueError(f"The events parameter must contain all {len(self.constants_service.LIFECYCLE_PATCH_EVENTS)} event definitions as part of a lifecycle patch/update request.")

        # validate event generic
        for event in definition['events']:

            # generic validation
            if 'name' not in event:
                raise ValueError("The name parameter must be defined for an event as part of a lifecycle patch/update request.")
            
            if event['name'].upper() not in self.constants_service.LIFECYCLE_PATCH_EVENTS:
                raise ValueError(f"The name parameter {event['name']} is not valid. It must be one of {','.join(self.constants_service.LIFECYCLE_PATCH_EVENTS)}.")

            if 'enabled' not in event:
                raise ValueError("The enabled parameter must be defined for an event as part of a lifecycle patch/update request.")

        # validate event logic
        event_details = {}
        for event in definition['events']:
            event_details[event['name']] = event['enabled']

        # check if logic step jumped
        if event_details[self.constants_service.EVENT_PATCH_AMI] == True:
            if event_details[self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_PATCH] == True:
                if event_details[self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH] == False:
                    self.rules_service.raise_error_failed_prerequisites(
                        current_event=self.constants_service.EVENT_PATCH_AMI,
                        previous_event=self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH,
                        previous_event_status="False"
                    )


    def validate_lifecycle_definition_create_update_request(self, definition) -> None:
        # validate that lifecycle_id is present
        if 'lifecycle_id' not in definition:
            raise ValueError("lifecycle_id must be defined as part of a lifecycle creation update request.")

        # perform common validation
        self._validate_common_create_update_request(definition)

        # validate that build_ami event is not enabled
        for event in definition['events']:
            if event['name'] == self.constants_service.EVENT_BUILD_AMI and event['enabled'] == True:
                raise ValueError(f"An update request assumes that an AMI has already been built. The {event['name']} must not be enabled during an update request.")


    def validate_lifecycle_definition_create_request(self, definition) -> None:
        # perform common validation
        self._validate_common_create_update_request(definition)
 
        # validate that build_ami event is enabled
        for event in definition['events']:
            if event['name'] == self.constants_service.EVENT_BUILD_AMI and event['enabled'] == False:
                raise ValueError(f"An AMI Build request requires that the {event['name']} is defined and enabled.")

        if event['name'] == self.constants_service.EVENT_BUILD_AMI:
            if 'product_ver' not in definition:
                raise ValueError(f"An AMI Build request requires that the product_ver attribute is defined.")
            if 'product_name' not in definition:
                raise ValueError(f"An AMI Build request requires that the product_name attribute is defined.")
            if 'commit_ref' not in definition:
                raise ValueError(f"An AMI Build request requires that the commit_ref attribute is defined.")

    
    def validate_lifecycle_definition_patch_request(
            self, 
            definition: dict, 
            isPost: bool
        ) -> None:
        # perform common validation
        self._validate_common_patch_update_request(definition)

        # if this is a patch creation event, perform additional validations
        if isPost:
            if 'commit_ref' not in definition:
                raise ValueError(f"An AMI Patch request requires that the commit_ref attribute is defined.")
            # validate patch component url is provided for patch create event
            for event in definition['events']:
                if event['name'] == self.constants_service.EVENT_PATCH_AMI:
                    if 'properties' not in definition:
                        raise ValueError(f"An AMI Patch request requires that the properties attribute is defined for event {event['name']}.")
                    if 'patch_component_url' not in definition['properties']:
                        raise ValueError(f"An AMI Patch request requires that the properties.patch_component_url attribute is defined for event {event['name']}.")
                    if 'patch_change_description' not in definition['properties']:
                        raise ValueError(f"An AMI Patch request requires that the properties.patch_change_description attribute is defined for event {event['name']}.")
                    if 'semver_bump_type' not in definition['properties']:
                         raise ValueError(f"An AMI Patch request requires that the properties.semver_bump_type attribute is defined for event {event['name']}.")
                    
            # validate that patch_ami event is enabled
            for event in definition['events']:
                if event['name'] == self.constants_service.EVENT_PATCH_AMI and event['enabled'] == False:
                    raise ValueError(f"An AMI Patch request requires that the {event['name']} is defined and enabled.")


    def validate_lifecycle_definition_receiver_request(self, definition) -> None:
        # validate that name is present
        if 'name' not in definition:
            raise ValueError("name must be defined as part of a lifecycle creation receiver request.")

        if 'status_date' not in definition:
            raise ValueError("status_date must be defined as part of a lifecycle creation receiver request.")

        if 'status' not in definition:
            raise ValueError("status must be defined as part of a lifecycle creation receiver request.")

        if definition['status'] not in self.constants_service.VALID_STATUSES:
            raise ValueError(f"The status parameter {definition['status']} is not valid. It must be one of {','.join(self.constants_service.VALID_STATUSES)}.")

        if 'properties' in definition and len(definition['properties']) == 0:
            raise ValueError("properties element is enabled but contains no elements. properties can not be empty as part of a lifecycle creation receiver request.")


    def validate_lifecycle_definition_create_receiver_request(self, definition) -> None:
        self.validate_lifecycle_definition_receiver_request(definition)


    def validate_lifecycle_definition_patch_receiver_request(self, definition) -> None:
        self.validate_lifecycle_definition_receiver_request(definition)


    def validate_lifecycle_definition_error_receiver_request(self, definition) -> None:
        if 'status_date' not in definition:
            raise ValueError("status_date must be defined as part of a lifecycle error request.")

        if 'status' not in definition:
            raise ValueError("status must be defined as part of a lifecycle error request.")

        if 'error_message' not in definition:
            raise ValueError("error_message must be defined as part of a lifecycle error request.")

        if 'stack_trace' not in definition:
            raise ValueError("stack_trace must be defined as part of a lifecycle error request.")


    def validate_lifecycle_qa_certifiction_request(self, definition) -> None:
        # validate lifecycle id
        if 'lifecycle_id' not in definition:
            raise ValueError("The lifecycle_id parameter must be defined as part of a lifecycle qa certification request.")
 
        # validate stack tag
        if 'stack_tag' not in definition:
            raise ValueError("The stack_tag parameter must be defined as part of a lifecycle qa certification request.")

        # validate certification status
        if 'certification_status' not in definition:
            raise ValueError("The certification_status parameter must be defined as part of a lifecycle qa certification request.")

        if 'properties' in definition:
            if len(definition['properties']) == 0:
                raise ValueError("properties element is enabled but contains no elements. properties can not be empty as part of a lifecycle qa certification request.")


    def validate_lifecycle_mark_for_production_request(self, definition) -> None:
        # validate lifecycle id
        if 'lifecycle_id' not in definition:
            raise ValueError("The lifecycle_id parameter must be defined as part of a lifecycle mark for production approval request.")
 
        # validate stack tag
        if 'stack_tag' not in definition:
            raise ValueError("The stack_tag parameter must be defined as part of a lifecycle mark for production approval request.")

        # validate approval status
        if 'approval_status' not in definition:
            raise ValueError("The approval_status parameter must be defined as part of a lifecycle mark for production approval request.")

        if 'properties' in definition:
            if len(definition['properties']) == 0:
                raise ValueError("properties element is enabled but contains no elements. properties can not be empty as part of a lifecycle mark for production approval request.")
