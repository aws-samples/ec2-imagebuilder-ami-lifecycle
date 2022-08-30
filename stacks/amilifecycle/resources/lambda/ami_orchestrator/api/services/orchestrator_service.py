#!/usr/bin/env python

"""
    orchestrator_service.py:
    service that orchestrates an AMI through the various stages
    of its lifecycle.
"""

import json
import logging
import os

from .ami_details_service import AmiDetailsService
from .aws_api_service import AwsApiService
from .cloudformation_service import CloudformationService
from .constants_service import ConstantsService
from .database_service import DatabaseService
from .lifecycle_service import LifecycleService
from .notifier_service import NotifierService
from .rules_service import RulesService
from .security_service import SecurityService
from .statemachine_service import StateMachineService

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class OrchestratorService:
    """
        Service that orchestrates an AMI through the various stages
        of its lifecycle.
    """

    # constants
    TEMPLATE_FILE = "lifecycle_event_notification.template"
    ERROR_TEMPLATE_FILE = "lifecycle_event_notification_error.template"
    WARNING_TEMPLATE_FILE = "lifecycle_event_notification_warning.template"
    INFO_TEMPLATE_FILE = "lifecycle_event_notification_info.template"

    # services
    database_service = DatabaseService()
    notifier_service = NotifierService()
    awsapi_service = AwsApiService()
    security_service = SecurityService()
    statemachine_service = StateMachineService()
    cloudformation_service = CloudformationService()
    constants_service = ConstantsService()
    ami_details_service = AmiDetailsService()
    rules_service = RulesService()
    lifecycle_service = LifecycleService()

    # environment variables
    smoke_tests_statemachine_export = os.environ['SMOKE_TESTS_STATEMACHINE_NAME']
    vulnerability_scans_statemachine_export = os.environ['VULNERABILITY_SCANS_STATEMACHINE_NAME']
    qa_cerify_req_statemachine_export = os.environ['QA_CERTIFICATION_STATEMACHINE_NAME']

    def get_service_name(self) -> str:
        return "orchestrator service"

    def _get_event_directive(self, event_name: str, events: list) -> tuple:
        for event in events:
            if event['name'] == event_name:
                if event['enabled']:
                    return True, event
                else:
                    return False, event

        raise ValueError(f"event_name: {event_name} not be found in events list {events}.")


    def _process_next_event_ami_creation(
            self, 
            event_name: str,
            event_description: str,
            operator: str,
            state_machine_input: str,
            event_properties: dict,
            statemachine_export_name: str,
            definition:dict
        ) -> bool:
    
        ######################################################
        # Process event
        ######################################################

        # check if the event is enabled
        is_event_enabled, lifecycle_event = self._get_event_directive(
            event_name=event_name,
            events=definition['inputs_ami_creation']['events']
        )

        # if event is enabled
        if is_event_enabled:

            # event is enabled, check if it is already completed
            is_event_completed = self._check_if_event_is_completed(
                event_name=event_name,
                events=definition['outputs_ami_creation']['events']
            )

            if is_event_completed == False:
                # check the rules to make sure event invocation can proceed
                self.rules_service.validate_event_can_proceed_create(
                    current_event=event_name,
                    defintion=definition
                )

                self.execute_state_machine(
                    statemachine_input=state_machine_input,
                    statemachine_export_name=statemachine_export_name,
                    definition=definition,
                    event_name=event_name,
                    event_description=event_description,
                    event_properties=event_properties
                )

                self.notifier_service.send_event_notification(
                    operator=operator,
                    definition=definition,
                    template_file=self.TEMPLATE_FILE
                )

                logger.info(f"Event {event_name} has been invoked on ami_details: {json.dumps(event_properties, indent=2)}")
                return True
            else:
                msg = (
                    f"An attempt has been made to process a {event_name} event " +
                    f"which has already been completed. " +
                    f"AMI Lifecycle events are immutable, once an event has been completed " +
                    f"successfully it can not be repeated. " +
                    f"This attempt has been ignored and no remediation action is required. " +
                    f"AMI Lifecycle events are sequential and must be completed in order." +
                    f"The order for AMI_CREATION events are: " +
                    f"{' -> '.join(self.constants_service.AMI_CREATION_SEQ)}. " +
                    f"The order for AMI_PATCH events are: " +
                    f"{' -> '.join(self.constants_service.AMI_PATCH_SEQ)}. " +
                    f"The input instructions for this AMI Creation API request are : " +
                    json.dumps(definition['inputs_ami_creation']['events'], indent=2)
                )
                logger.info(msg)

                return False

        return False


    def _process_next_event_ami_patch(
            self, 
            event_name: str,
            event_description: str,
            operator: str,
            state_machine_input: str,
            event_properties: dict,
            statemachine_export_name: str,
            definition:dict
        ):
    
        ######################################################
        # Process event
        ######################################################

        # check if the event is enabled
        is_event_enabled, lifecycle_event = self._get_event_directive(
            event_name=event_name,
            events=definition["inputs_ami_patch"]["events"]
        )

        # if event is enabled
        if is_event_enabled:

            # event is enabled, check if it is already completed
            is_event_completed = self._check_if_event_is_completed(
                event_name=event_name,
                events=self.lifecycle_service.get_ami_current_patch_events(definition)
            )

            if is_event_completed == False:
                # check the rules to make sure event invocation can proceed
                self.rules_service.validate_event_can_proceed_patch(
                    current_event=event_name,
                    defintion=definition
                )

                self.execute_state_machine(
                    statemachine_input=state_machine_input,
                    statemachine_export_name=statemachine_export_name,
                    definition=definition,
                    event_name=event_name,
                    event_description=event_description,
                    event_properties=event_properties
                )

                self.notifier_service.send_event_notification(
                    operator=operator,
                    definition=definition,
                    template_file=self.TEMPLATE_FILE
                )

                logger.info(f"Event {event_name} has been invoked on ami_details: {json.dumps(event_properties, indent=2)}")
                return True
            else:
                msg = (
                    f"An attempt has been made to process a {event_name} event " +
                    f"which has already been completed. " +
                    f"AMI Lifecycle events are immutable, once an event has been completed " +
                    f"successfully it can not be repeated. " +
                    f"This attempt has been ignored and no remediation action is required. " +
                    f"AMI Lifecycle events are sequential and must be completed in order." +
                    f"The order for AMI_CREATION events are: " +
                    f"{' -> '.join(self.constants_service.AMI_CREATION_SEQ)}. " +
                    f"The order for AMI_PATCH events are: " +
                    f"{' -> '.join(self.constants_service.AMI_PATCH_SEQ)}. " +
                    f"The input instructions for this AMI Patch API request are : " +
                    json.dumps(definition['inputs_ami_patch']['events'], indent=2)
                )
                logger.info(msg)

                return False
        
        return False


    def _handle_next_event_ami_creation(self, definition:dict):
        
        ami_detail = self.ami_details_service.get_ami_details_for_testing(definition)

        ######################################################
        # Process SMOKE TESTS event
        ######################################################

        smoke_test_state_machine_input = {
            "lifecycle_id": definition['lifecycle_id'],
            "operation_type": self.constants_service.AMI_CREATION,
            "cfn_stack_name": definition['stack_tag'],
            "ami_id": ami_detail['image'],
            "ami_name": ami_detail['name'],
            "ami_region": ami_detail['region'],
            "ami_owner": ami_detail['accountId']
        }

        smoke_test_formatted_state_machine_input = self.statemachine_service.generate_state_machine_input(
            state_machine_input = smoke_test_state_machine_input
        )

        smoke_test_event_properties = {
            "smoke_test_ami_id": ami_detail['image'],
            "smoke_test_ami_name": ami_detail['name'],
            "smoke_test_ami_region": ami_detail['region'],
            "smoke_test_ami_owner": ami_detail['accountId']
        }

        is_smoke_test_required = self._process_next_event_ami_creation(
            event_name=self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE,
            event_description=self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE_DESCRIPTION,
            operator="AMI_CREATE_SMOKE_TEST_EXECUTION",
            state_machine_input=smoke_test_formatted_state_machine_input,
            statemachine_export_name=self.smoke_tests_statemachine_export,
            event_properties=smoke_test_event_properties,
            definition=definition
        )

        if is_smoke_test_required:
            msg = (
                f"Event {self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE} is the " +
                "current event to be executed."
            )
            return msg


        ######################################################
        # Process VULNERABILITY SCANS event
        ######################################################

        vulnerability_scan_state_machine_input = {
            "lifecycle_id": definition['lifecycle_id'],
            "operation_type": self.constants_service.AMI_CREATION,
            "cfn_stack_name": definition['stack_tag'],
            "ami_id": ami_detail['image'],
            "ami_name": ami_detail['name'],
            "ami_region": ami_detail['region'],
            "ami_owner": ami_detail['accountId']
        }

        vulnerability_scan_formatted_state_machine_input = self.statemachine_service.generate_state_machine_input(
            state_machine_input = vulnerability_scan_state_machine_input
        )

        vulnerability_scan_event_properties = {
            "vulnerability_scan_ami_id": ami_detail['image'],
            "vulnerability_scan_ami_name": ami_detail['name'],
            "vulnerability_scan_ami_region": ami_detail['region'],
            "vulnerability_scan_ami_owner": ami_detail['accountId']
        }

        is_vulnerability_scan_required = self._process_next_event_ami_creation(
            event_name=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE,
            event_description=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE_DESCRIPTION,
            operator="AMI_CREATE_VULNERABILITY_SCANS_EXECUTION",
            state_machine_input=vulnerability_scan_formatted_state_machine_input,
            statemachine_export_name=self.vulnerability_scans_statemachine_export,
            event_properties=vulnerability_scan_event_properties,
            definition=definition
        )

        if is_vulnerability_scan_required:
            msg = (
                f"Event {self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE} is the " +
                "current event to be executed."
            )
            return msg

        ######################################################
        # Process QA_CERTIFICATION_REQUEST event
        ######################################################

        qa_certify_req_state_machine_input = {
            "lifecycle_id": definition['lifecycle_id'],
            "cfn_stack_name": definition['stack_tag'],
            "api_url": self.awsapi_service.get_base_endpoint(),
            "ami_id": ami_detail['image'],
            "ami_name": ami_detail['name'],
            "ami_region": ami_detail['region'],
            "ami_owner": ami_detail['accountId']
        }

        qa_certify_req_formatted_state_machine_input = self.statemachine_service.generate_state_machine_input(
            state_machine_input = qa_certify_req_state_machine_input
        )

        qa_certify_req_event_properties = {
            "qa_certification_request_ami_id": ami_detail['image'],
            "qa_certification_request_ami_name": ami_detail['name'],
            "qa_certification_request_ami_region": ami_detail['region'],
            "qa_certification_request_ami_owner": ami_detail['accountId']
        }

        is_qa_certify_req_required = self._process_next_event_ami_creation(
            event_name=self.constants_service.EVENT_QA_CERTIFICATION_REQUEST,
            event_description=self.constants_service.EVENT_QA_CERTIFICATION_REQUEST_DESCRIPTION,
            operator="AMI_CREATE_QA_CERTIFICATION_REQUEST",
            state_machine_input=qa_certify_req_formatted_state_machine_input,
            statemachine_export_name=self.qa_cerify_req_statemachine_export,
            event_properties=qa_certify_req_event_properties,
            definition=definition
        )

        if is_qa_certify_req_required:
            msg = (
                f"Event {self.constants_service.EVENT_QA_CERTIFICATION_REQUEST} is the " +
                "current event to be executed."
            )
            return msg

        # no further events to process
        msg = (
            f"The AMI Orchestrator has determined that no further events " +
            f"need to be processed within the context of this AMI Creation API request. " +
            f"The referenced API request was received with the following lifecycle " +
            f"instructions: " +
            json.dumps(definition['inputs_ami_creation'], indent=2)
        )
        logger.info(msg)

        template_attributes = {}
        template_attributes['operator'] = "ORCHESTRATOR_SERVICE"
        template_attributes['stack_tag'] = definition['stack_tag']
        template_attributes['lifecycle_id'] = definition['lifecycle_id']
        template_attributes['info_message'] = msg
        template_attributes['status_url'] = self.awsapi_service.get_ami_status_endpoint(definition['lifecycle_id'])

        self.notifier_service.send_event_notification(
            operator="ORCHESTRATOR_SERVICE",
            definition=template_attributes,
            template_file=self.INFO_TEMPLATE_FILE
        )

        return True


    def _handle_next_event_ami_patch(self, definition:dict):
        
        ami_detail = self.ami_details_service.get_ami_details_for_testing_patch(definition)

        ######################################################
        # Process SMOKE TESTS event
        ######################################################

        smoke_test_state_machine_input = {
            "lifecycle_id": definition['lifecycle_id'],
            "operation_type": self.constants_service.AMI_PATCH,
            "cfn_stack_name": definition['stack_tag'],
            "ami_id": ami_detail['image'],
            "ami_name": ami_detail['name'],
            "ami_region": ami_detail['region'],
            "ami_owner": ami_detail['accountId']
        }

        smoke_test_formatted_state_machine_input = self.statemachine_service.generate_state_machine_input(
            state_machine_input = smoke_test_state_machine_input
        )

        smoke_test_event_properties = {
            "smoke_test_ami_id": ami_detail['image'],
            "smoke_test_ami_name": ami_detail['name'],
            "smoke_test_ami_region": ami_detail['region'],
            "smoke_test_ami_owner": ami_detail['accountId']
        }

        is_smoke_test_required = self._process_next_event_ami_patch(
            event_name=self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH,
            event_description=self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH_DESCRIPTION,
            operator="AMI_PATCH_SMOKE_TEST_EXECUTION",
            state_machine_input=smoke_test_formatted_state_machine_input,
            statemachine_export_name=self.smoke_tests_statemachine_export,
            event_properties=smoke_test_event_properties,
            definition=definition
        )

        if is_smoke_test_required:
            msg = (
                f"Event {self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH} is the " +
                "current event to be executed."
            )
            return msg


        ######################################################
        # Process VULNERABILITY SCANS event
        ######################################################

        vulnerability_scan_state_machine_input = {
            "lifecycle_id": definition['lifecycle_id'],
            "operation_type": self.constants_service.AMI_PATCH,
            "cfn_stack_name": definition['stack_tag'],
            "ami_id": ami_detail['image'],
            "ami_name": ami_detail['name'],
            "ami_region": ami_detail['region'],
            "ami_owner": ami_detail['accountId']
        }

        vulnerability_scan_formatted_state_machine_input = self.statemachine_service.generate_state_machine_input(
            state_machine_input = vulnerability_scan_state_machine_input
        )

        vulnerability_scan_event_properties = {
            "vulnerability_scan_ami_id": ami_detail['image'],
            "vulnerability_scan_ami_name": ami_detail['name'],
            "vulnerability_scan_ami_region": ami_detail['region'],
            "vulnerability_scan_ami_owner": ami_detail['accountId']
        }

        is_vulnerability_scan_required = self._process_next_event_ami_patch(
            event_name=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_PATCH,
            event_description=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_PATCH_DESCRIPTION,
            operator="AMI_PATCH_VULNERABILITY_SCANS_EXECUTION",
            state_machine_input=vulnerability_scan_formatted_state_machine_input,
            statemachine_export_name=self.vulnerability_scans_statemachine_export,
            event_properties=vulnerability_scan_event_properties,
            definition=definition
        )

        if is_vulnerability_scan_required:
            msg = (
                f"Event {self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_PATCH} is the " +
                "current event to be executed."
            )
            return msg

        # no further events to process
        msg = (
            f"The AMI Orchestrator has determined that no further events " +
            f"need to be processed within the context of this AMI Patch API request. " +
            f"The referenced API request was received with the following lifecycle " +
            f"instructions: " +
            json.dumps(definition['inputs_ami_patch']['events'], indent=2)
        )
        logger.info(msg)

        template_attributes = {}
        template_attributes['operator'] = "ORCHESTRATOR_SERVICE"
        template_attributes['stack_tag'] = definition['stack_tag']
        template_attributes['lifecycle_id'] = definition['lifecycle_id']
        template_attributes['info_message'] = msg
        template_attributes['status_url'] = self.awsapi_service.get_ami_status_endpoint(definition['lifecycle_id'])

        self.notifier_service.send_event_notification(
            operator="ORCHESTRATOR_SERVICE",
            definition=template_attributes,
            template_file=self.INFO_TEMPLATE_FILE
        )

        return True


    def _check_if_event_is_completed(self, event_name: str, events: dict) -> bool:
        for event in events:
            if event['name'] == event_name:
                if event['status'] == self.constants_service.STATUS_COMPLETED:
                    return True
        
        return False


    def handle_next_event(self, api_type: str, definition:dict):

        # orchestrate tasks for AMI_CREATION
        if api_type == self.constants_service.AMI_CREATION:
            return self._handle_next_event_ami_creation(definition)

        # orchestrate tasks for AMI_CREATION
        if api_type == self.constants_service.AMI_PATCH:
            return self._handle_next_event_ami_patch(definition)


    def execute_state_machine(
            self, 
            statemachine_input: str,
            definition: dict,
            statemachine_export_name: str,
            event_name: str,
            event_description: str,
            event_properties: dict
        ) -> None:
        # grab the state machine arn from cloudformation export
        statemachine_arn = self.cloudformation_service.get_stack_output_value(
            cfn_stack_name=self.constants_service.CLOUDFORMATION_STACK_AMI_LIFECYCLE,
            output_name=statemachine_export_name
        )

        # start the state machine and begin the creation lifecycle process
        execution_arn, execution_startdate = self.statemachine_service.execute_state_machine(
            statemachine_arn=statemachine_arn,
            statemachine_input=statemachine_input
        )

        # create an event in progress
        event_in_progress = {
            'name': event_name,
            'description': event_description,
            'statemachine_arn': statemachine_arn,
            'statemachine_input': statemachine_input,
            'execution_arn': execution_arn,
            'execution_startdate': execution_startdate,
            'properties': event_properties
        }

        # persist event in progress to ami lifecycle
        self.database_service.update_event_in_progress(
            lifecycle_id=definition['lifecycle_id'], 
            event_in_progress=event_in_progress
        )
