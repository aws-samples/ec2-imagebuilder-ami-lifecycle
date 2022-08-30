#!/usr/bin/env python

"""
    rules_service.py:
    service that enforces the business rules of the AMI Lifecycle events.
"""

import logging

from .constants_service import ConstantsService

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class RulesService:
    """
        Service that enforces the business rules of the AMI Lifecycle events.
    """

    constants_service = ConstantsService()

    def get_service_name(self) -> str:
        return "rules service"


    def raise_error_failed_prerequisites(
            self,
            current_event: str,
            previous_event: str,
            previous_event_status: str
        ) -> None: 
        msg = (
            f"Unable to proceed with {current_event} event " +
            f"as a previous event {previous_event} is " +
            f"in {previous_event_status} state. " +
            f"AMI Lifecycle events are sequential and must be completed in order." +
            f"The order for AMI_CREATION events are: " +
            f"{' -> '.join(self.constants_service.AMI_CREATION_SEQ)}. " +
            f"The order for AMI_PATCH events are: " +
            f"{' -> '.join(self.constants_service.AMI_PATCH_SEQ)}."
        )
        raise ValueError(msg)


    def raise_error_immutable_event(
            self,
            current_event: str
        ) -> None: 
        msg = (
            f"Unable to proceed with {current_event} event " +
            f"as it has already been completed. " +
            f"AMI Lifecycle events are immutable, once an event has been completed " +
            f"successfully it can not be repeated. " +
            f"AMI Lifecycle events are sequential and must be completed in order." +
            f"The order for AMI_CREATION events are: " +
            f"{' -> '.join(self.constants_service.AMI_CREATION_SEQ)}. " +
            f"The order for AMI_PATCH events are: " +
            f"{' -> '.join(self.constants_service.AMI_PATCH_SEQ)}."
        )
        raise ValueError(msg)


    def _validate_event_completed(
            self, 
            events:dict,
            event_name: str
        ) -> str:

        for event in events:
            if event['name'] == event_name:
                return event['status']
        
        return self.constants_service.STATUS_NOT_STARTED


    def _validate_event_ami_smoke_tests_can_proceed(            
            self, 
            definition:dict
        ) -> bool:
        # check 01 -confirm that the AMI_BUILD event completed successfully
        ami_build_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_BUILD_AMI
        )
        if ami_build_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE,
                previous_event=self.constants_service.EVENT_BUILD_AMI,
                previous_event_status=ami_build_status
            )

        # check 02 - confirm that there is no previous SMOKE_TEST in the completed state
        # events are immutable so a completed event can not be repeated
        smoke_test_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE
        )
        if smoke_test_status == self.constants_service.STATUS_COMPLETED:
            self.raise_error_immutable_event(
                current_event=self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE
            )

        # all checks passed - we can proceed
        return True


    def _validate_event_ami_vulnerability_scans_can_proceed(            
            self, 
            definition:dict
        ) -> bool:
        # check 01 -confirm that the AMI_BUILD event completed successfully
        ami_build_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_BUILD_AMI
        )
        if ami_build_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE,
                previous_event=self.constants_service.EVENT_BUILD_AMI,
                previous_event_status=ami_build_status
            )

        # check 02 - confirm that the SMOKE_TEST event completed successfully
        # events are immutable so a completed event can not be repeated
        smoke_test_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE
        )
        if smoke_test_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE,
                previous_event=self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE,
                previous_event_status=smoke_test_status
            )

        # check 03 - confirm that there is no previous VULNERABILITY_SCAN event is in the completed state
        vulnerability_scan_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE
        )
        if vulnerability_scan_status == self.constants_service.STATUS_COMPLETED:
            self.raise_error_immutable_event(
                current_event=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE
            )

        # all checks passed - we can proceed
        return True


    def _validate_event_qa_certification_request_can_proceed(            
            self, 
            definition:dict
        ) -> bool:
        # check 01 -confirm that the AMI_BUILD event completed successfully
        ami_build_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_BUILD_AMI
        )
        if ami_build_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_QA_CERTIFICATION_REQUEST,
                previous_event=self.constants_service.EVENT_BUILD_AMI,
                previous_event_status=ami_build_status
            )

        # check 02 - confirm that the SMOKE_TEST event completed successfully
        # events are immutable so a completed event can not be repeated
        smoke_test_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE
        )
        if smoke_test_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_QA_CERTIFICATION_REQUEST,
                previous_event=self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE,
                previous_event_status=smoke_test_status
            )

        # check 03 - confirm that the VULNERABILITY_SCAN event completed successfully
        # events are immutable so a completed event can not be repeated
        vulnerability_scan_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE
        )
        if vulnerability_scan_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_QA_CERTIFICATION_REQUEST,
                previous_event=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE,
                previous_event_status=vulnerability_scan_status
            )

        # check 04 - confirm that there is no previous QA_CERTIFICATION_REQUEST event is in the completed state
        qa_certify_req_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_QA_CERTIFICATION_REQUEST
        )
        if qa_certify_req_status == self.constants_service.STATUS_COMPLETED:
            self.raise_error_immutable_event(
                current_event=self.constants_service.EVENT_QA_CERTIFICATION_REQUEST
            )

        # all checks passed - we can proceed
        return True


    def _validate_event_qa_certification_response_can_proceed(            
            self, 
            definition:dict
        ) -> None:
        # check 01 -confirm that the AMI_BUILD event completed successfully
        ami_build_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_BUILD_AMI
        )
        if ami_build_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_QA_CERTIFICATION_RESPONSE,
                previous_event=self.constants_service.EVENT_BUILD_AMI,
                previous_event_status=ami_build_status
            )

        # check 02 - confirm that the SMOKE_TEST event completed successfully
        # events are immutable so a completed event can not be repeated
        smoke_test_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE
        )
        if smoke_test_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_QA_CERTIFICATION_RESPONSE,
                previous_event=self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE,
                previous_event_status=smoke_test_status
            )

        # check 03 - confirm that the VULNERABILITY_SCAN event completed successfully
        # events are immutable so a completed event can not be repeated
        vulnerability_scan_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE
        )
        if vulnerability_scan_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_QA_CERTIFICATION_RESPONSE,
                previous_event=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE,
                previous_event_status=vulnerability_scan_status
            )

        # check 04 - confirm that the QA_CERTIFICATION_REQUEST event completed successfully
        # events are immutable so a completed event can not be repeated
        qa_certify_req_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_QA_CERTIFICATION_REQUEST
        )
        if qa_certify_req_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_QA_CERTIFICATION_RESPONSE,
                previous_event=self.constants_service.EVENT_QA_CERTIFICATION_REQUEST,
                previous_event_status=qa_certify_req_status
            )

        # check 05 - confirm that there is no previous QA_CERTIFICATION_RESPONSE event is in the completed state
        qa_certify_res_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_QA_CERTIFICATION_RESPONSE
        )
        if qa_certify_res_status == self.constants_service.STATUS_COMPLETED:
            self.raise_error_immutable_event(
                current_event=self.constants_service.EVENT_QA_CERTIFICATION_RESPONSE
            )

    def _validate_event_mark_for_production_can_proceed(            
            self, 
            definition:dict
        ) -> bool:
        # check 01 -confirm that the AMI_BUILD event completed successfully
        ami_build_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_BUILD_AMI
        )
        if ami_build_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE,
                previous_event=self.constants_service.EVENT_BUILD_AMI,
                previous_event_status=ami_build_status
            )

        # check 02 - confirm that the SMOKE_TEST event completed successfully
        # events are immutable so a completed event can not be repeated
        smoke_test_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE
        )
        if smoke_test_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE,
                previous_event=self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE,
                previous_event_status=smoke_test_status
            )

        # check 03 - confirm that the VULNERABILITY_SCAN event completed successfully
        # events are immutable so a completed event can not be repeated
        vulnerability_scan_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE
        )
        if vulnerability_scan_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE,
                previous_event=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE,
                previous_event_status=vulnerability_scan_status
            )

        # check 04 - confirm that the QA_CERTIFICATION_REQUEST event completed successfully
        # events are immutable so a completed event can not be repeated
        qa_certify_req_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_QA_CERTIFICATION_REQUEST
        )
        if qa_certify_req_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE,
                previous_event=self.constants_service.EVENT_QA_CERTIFICATION_REQUEST,
                previous_event_status=qa_certify_req_status
            )

        # check 05 - confirm that the QA_CERTIFICATION_RESPONSE event completed successfully
        # events are immutable so a completed event can not be repeated
        qa_certify_req_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_QA_CERTIFICATION_RESPONSE
        )
        if qa_certify_req_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE,
                previous_event=self.constants_service.EVENT_QA_CERTIFICATION_RESPONSE,
                previous_event_status=qa_certify_req_status
            )

        # check 06 - confirm that there is no previous MARK_FOR_PRODUCTION event is in the completed state
        mark_for_production_status = self._validate_event_completed(
            events=definition['outputs_ami_creation']['events'],
            event_name=self.constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE
        )
        if mark_for_production_status == self.constants_service.STATUS_COMPLETED:
            self.raise_error_immutable_event(
                current_event=self.constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE
            )

        # all checks passed - we can proceed
        return True


    def _validate_event_ami_smoke_tests_can_proceed_patch(            
            self, 
            definition:dict
        ) -> bool:
        # check 01 -confirm that the AMI_PATCH event completed successfully
        ami_patch_status = self._validate_event_completed(
            events=definition['outputs_ami_patch']['patch_history']['current']['events'],
            event_name=self.constants_service.EVENT_PATCH_AMI
        )
        if ami_patch_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH,
                previous_event=self.constants_service.EVENT_PATCH_AMI,
                previous_event_status=ami_patch_status
            )

        # check 02 - confirm that there is no previous SMOKE_TEST in the completed state
        # events are immutable so a completed event can not be repeated
        smoke_test_status = self._validate_event_completed(
            events=definition['outputs_ami_patch']['patch_history']['current']['events'],
            event_name=self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH
        )
        if smoke_test_status == self.constants_service.STATUS_COMPLETED:
            self.raise_error_immutable_event(
                current_event=self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH
            )

        # all checks passed - we can proceed
        return True


    def _validate_event_ami_vulnerability_scans_can_proceed_patch(            
            self, 
            definition:dict
        ) -> bool:
        # check 01 -confirm that the AMI_BUILD event completed successfully
        ami_patch_status = self._validate_event_completed(
            events=definition['outputs_ami_patch']['patch_history']['current']['events'],
            event_name=self.constants_service.EVENT_PATCH_AMI
        )
        if ami_patch_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_PATCH,
                previous_event=self.constants_service.EVENT_PATCH_AMI,
                previous_event_status=ami_patch_status
            )

        # check 02 - confirm that the SMOKE_TEST event completed successfully
        # events are immutable so a completed event can not be repeated
        smoke_test_status = self._validate_event_completed(
            events=definition['outputs_ami_patch']['patch_history']['current']['events'],
            event_name=self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH
        )
        if smoke_test_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_PATCH,
                previous_event=self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH,
                previous_event_status=smoke_test_status
            )

        # check 03 - confirm that there is no previous VULNERABILITY_SCAN event is in the completed state
        vulnerability_scan_status = self._validate_event_completed(
            events=definition['outputs_ami_patch']['patch_history']['current']['events'],
            event_name=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_PATCH
        )
        if vulnerability_scan_status == self.constants_service.STATUS_COMPLETED:
            self.raise_error_immutable_event(
                current_event=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_PATCH
            )

        # all checks passed - we can proceed
        return True


    def _validate_event_mark_for_production_can_proceed_patch(            
            self, 
            definition:dict
        ) -> bool:
        # check 01 -confirm that the AMI_BUILD event completed successfully
        ami_patch_status = self._validate_event_completed(
            events=definition['outputs_ami_patch']['patch_history']['current']['events'],
            event_name=self.constants_service.EVENT_PATCH_AMI
        )
        if ami_patch_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_MARK_FOR_PRODUCTION_PATCH,
                previous_event=self.constants_service.EVENT_PATCH_AMI,
                previous_event_status=ami_patch_status
            )

        # check 02 - confirm that the SMOKE_TEST event completed successfully
        # events are immutable so a completed event can not be repeated
        smoke_test_status = self._validate_event_completed(
            events=definition['outputs_ami_patch']['patch_history']['current']['events'],
            event_name=self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH
        )
        if smoke_test_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_MARK_FOR_PRODUCTION_PATCH,
                previous_event=self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH,
                previous_event_status=smoke_test_status
            )

        # check 03 - confirm that the VULNERABILITY_SCAN event completed successfully
        # events are immutable so a completed event can not be repeated
        vulnerability_scan_status = self._validate_event_completed(
            events=definition['outputs_ami_patch']['patch_history']['current']['events'],
            event_name=self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_PATCH
        )
        if vulnerability_scan_status != self.constants_service.STATUS_COMPLETED:
            self.raise_error_failed_prerequisites(
                current_event=self.constants_service.EVENT_MARK_FOR_PRODUCTION_PATCH,
                previous_event=self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH,
                previous_event_status=vulnerability_scan_status
            )

        # check 04 - confirm that there is no previous MARK_FOR_PRODUCTION event is in the completed state
        mark_for_production_status = self._validate_event_completed(
            events=definition['outputs_ami_patch']['patch_history']['current']['events'],
            event_name=self.constants_service.EVENT_MARK_FOR_PRODUCTION_PATCH
        )
        if mark_for_production_status == self.constants_service.STATUS_COMPLETED:
            self.raise_error_immutable_event(
                current_event=self.constants_service.EVENT_MARK_FOR_PRODUCTION_PATCH
            )

        # all checks passed - we can proceed
        return True


    def validate_event_can_proceed_create(
            self, 
            current_event: str, 
            defintion:dict
        ) -> bool:

        # handle SMOKE TESTS event
        if current_event == self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE:
            return self._validate_event_ami_smoke_tests_can_proceed(
                definition=defintion
            )

        # handle VULNERABILITY SCANS event
        if current_event == self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE:
            return self._validate_event_ami_vulnerability_scans_can_proceed(
                definition=defintion
            ) 

        # handle QA CERTIFICATION REQUEST event
        if current_event == self.constants_service.EVENT_QA_CERTIFICATION_REQUEST:
            return self._validate_event_qa_certification_request_can_proceed(
                definition=defintion
            ) 

        # handle QA CERTIFICATION RESPONSE event
        if current_event == self.constants_service.EVENT_QA_CERTIFICATION_RESPONSE:
            return self._validate_event_qa_certification_response_can_proceed(
                definition=defintion
            ) 

        # handle MARK FOR PRODUCTION event
        if current_event == self.constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE:
            return self._validate_event_mark_for_production_can_proceed(
                definition=defintion
            ) 


    def validate_event_can_proceed_patch(
            self, 
            current_event: str, 
            defintion:dict
        ) -> bool:

        # handle SMOKE TESTS event
        if current_event == self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH:
            return self._validate_event_ami_smoke_tests_can_proceed_patch(
                definition=defintion
            )

        # handle VULNERABILITY SCANS event
        if current_event == self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_PATCH:
            return self._validate_event_ami_vulnerability_scans_can_proceed_patch(
                definition=defintion
            ) 

        # handle MARK FOR PRODUCTION event
        if current_event == self.constants_service.EVENT_MARK_FOR_PRODUCTION_PATCH:
            return self._validate_event_mark_for_production_can_proceed_patch(
                definition=defintion
            ) 


    def validate_patching_prerequisites(self, definition: dict) -> None:

        # check that the lifecycle has a creation event in a valid and completed state
        if 'outputs_ami_creation' in definition:
            if 'events' in definition['outputs_ami_creation']:
                if len(definition['outputs_ami_creation']['events']) != len(self.constants_service.AMI_CREATION_SEQ):
                    raise ValueError(
                        f"Number of actual AMI Creation events: {len(definition['outputs_ami_creation']['events'])} " +
                        f"does not match the number of expected AMI Creation events: {len(self.constants_service.AMI_CREATION_SEQ)}. " +
                        "An AMI Patch request can only proceed when all AMI Creation events have completed " +
                        "successfully. Ensure that the following AMI Creation events are completed: " +
                        ' -> '.join(self.constants_service.AMI_CREATION_SEQ)
                    )
                for event in definition['outputs_ami_creation']['events']:
                    if event['status'] != self.constants_service.STATUS_COMPLETED:
                        raise ValueError(
                            f"AMI Creation event: {event['name']} has status {event['status']}. " +
                            "An AMI Patch operation can only be peformed when " +
                            "all AMI Creation events have been completed. AMi Creation " +
                            f"event: {event['name']} has status {event['status']}."
                        )
            else:
                raise ValueError(
                    "The outputs_ami_creation attribute is missing the events array. " +
                    "An AMI Patch request can only proceed when all AMI Creation events have completed " +
                    "successfully. Ensure that the following AMI Creation events are completed: " +
                    ' -> '.join(self.constants_service.AMI_CREATION_SEQ)
                )
        else:
            raise ValueError(
                "The outputs_ami_creation attribute is missing. " +
                "An AMI Patch request can only proceed when all AMI Creation events have completed " +
                "successfully. Ensure that the following AMI Creation events are completed: " +
                ' -> '.join(self.constants_service.AMI_CREATION_SEQ)
            )
