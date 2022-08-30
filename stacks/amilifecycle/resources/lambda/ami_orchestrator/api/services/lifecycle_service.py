#!/usr/bin/env python

"""
    lifecycle_service.py:
    service that provides common utility functions for querying
    and interacting with a Lifecycle object.
"""

import logging

from .constants_service import ConstantsService

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

class LifecycleService:
    """
        Service that provides common utility functions for querying
        and interacting with a Lifecycle object.
    """

    constants_service = ConstantsService()

    def get_ami_creation_events(self, definition: dict) -> list:
        if "outputs_ami_creation" in definition:
            if "events" in definition["outputs_ami_creation"]:
                return definition["outputs_ami_creation"]["events"]
                
        return []

    def get_ami_current_patch_events(self, definition: dict) -> list:
        if "outputs_ami_patch" in definition:
            if 'patch_history' in definition["outputs_ami_patch"]:
                if 'current' in definition["outputs_ami_patch"]["patch_history"]:
                    if "events" in definition["outputs_ami_patch"]["patch_history"]["current"]:
                        return definition["outputs_ami_patch"]["patch_history"]["current"]["events"]
                
        return []

    def get_ami_detail_by_account_id(
            self, 
            event: dict,
            event_name: str,
            account_id: str
        ) -> dict:
        if event['name'] == event_name:
            if 'properties' in event:
                if 'ami_details' in event['properties']:
                    for ami_detail in event['properties']['ami_details']:
                        if ami_detail['accountId'] == account_id:
                            return ami_detail

        return None

    def get_patch_history(self, definition: dict) -> list:
        if "outputs_ami_patch" in definition:
            if 'patch_history' in definition["outputs_ami_patch"]:
                if 'historical' in definition["outputs_ami_patch"]["patch_history"]:
                    return definition["outputs_ami_patch"]["patch_history"]["historical"]

        return []
