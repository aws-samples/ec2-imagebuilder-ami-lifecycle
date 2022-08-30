#!/usr/bin/env python

"""
    database_service.py:
    service that interacts with DynamoDB for all persistence and
    retrieval operations related to the AMI Lifecycles.
"""

import datetime
import functools
import json
import logging
import os
import uuid

import boto3
import semver
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from botocore.exceptions import ClientError

from .ami_details_service import AmiDetailsService
from .aws_api_service import AwsApiService
from .constants_service import ConstantsService

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

class DatabaseService:
    """
        Service that interacts with DynamoDB for all persistence and
        retrieval operations related to the AMI Lifecycles.
    """

    AMI_LIFECYCLE_STATE_TABLENAME = os.environ['AMI_LIFECYCLE_STATE_TABLENAME']
    AMI_LOOKUP_TABLENAME = os.environ['AMI_LOOKUP_TABLENAME']
    AMI_SEMVER_SEED_TABLENAME = os.environ['AMI_SEMVER_SEED_TABLENAME']
    DEFAULT_AMI_SEMVER_SEED = os.environ['DEFAULT_AMI_SEMVER_SEED']
    dynamodb = boto3.client('dynamodb')

    awsapi_service = AwsApiService()
    constants_service = ConstantsService()
    ami_details_service = AmiDetailsService()
    
    serializer= TypeSerializer()
    deserializer = TypeDeserializer()


    def get_service_name(self) -> str:
        return "database service"


    def create_lifecycle(self, definition: dict) -> dict:
        
        definition['lifecycle_id'] = str(uuid.uuid4())
        definition['creation_date'] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        definition['inputs_ami_creation'] = {}
        definition['inputs_ami_creation']['events'] = json.loads(json.dumps(definition['events']))
        
        # add an attribute for the timeline
        definition['timeline'] = {}
        timeline_url = self.awsapi_service.get_ami_creation_timeline_endpoint(definition['lifecycle_id'])
        definition['timeline']['ami_creation'] = timeline_url

        # remove the keys that are not to be persisted
        del definition['api_key']
        del definition['events']

        serialized_data = self.serializer.serialize(definition)
        
        # update item with new values
        self.dynamodb.put_item(
            TableName=self.AMI_LIFECYCLE_STATE_TABLENAME, 
            Item=serialized_data['M']
        )

        return definition


    def create_update_lifecycle(self, lifecycle_definition: dict) -> dict:

        curr_lifecycle = self.get_lifecycle_by_lifecycle_id(lifecycle_definition['lifecycle_id'])

        # begin updates on lifecycle
        curr_lifecycle['owner'] = lifecycle_definition['owner']
        curr_lifecycle['update_date'] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        curr_lifecycle['notifications'] = json.loads(json.dumps(lifecycle_definition['notifications']))
        curr_lifecycle['inputs_ami_creation']['events'] = json.loads(json.dumps(lifecycle_definition['events']))
        
        if 'properties' in lifecycle_definition:
            if 'properties' in curr_lifecycle:
                curr_lifecycle['properties'] = {**lifecycle_definition['properties'], **curr_lifecycle['properties']}
            else:
                curr_lifecycle['properties'] = lifecycle_definition['properties']

        serialized_data = self.serializer.serialize(curr_lifecycle)
        
        # update item with new values
        self.dynamodb.put_item(
            TableName=self.AMI_LIFECYCLE_STATE_TABLENAME, 
            Item=serialized_data['M']
        )

        return curr_lifecycle


    def patch_create_update_lifecycle(self, lifecycle_definition: dict) -> dict:

        curr_lifecycle = self.get_lifecycle_by_lifecycle_id(lifecycle_definition['lifecycle_id'])

        if 'inputs_ami_patch' not in curr_lifecycle:
            curr_lifecycle['inputs_ami_patch'] = {}

        # begin updates on lifecycle
        curr_lifecycle['inputs_ami_patch']['owner'] = lifecycle_definition['owner']
        curr_lifecycle['inputs_ami_patch']['update_date'] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        curr_lifecycle['inputs_ami_patch']['notifications'] = json.loads(json.dumps(lifecycle_definition['notifications']))
        curr_lifecycle['inputs_ami_patch']['events'] = json.loads(json.dumps(lifecycle_definition['events']))
        curr_lifecycle['inputs_ami_patch']['commit_ref'] = lifecycle_definition['commit_ref']

        if 'properties' in lifecycle_definition:
            if 'properties' not in curr_lifecycle['inputs_ami_patch']:
                curr_lifecycle['inputs_ami_patch']['properties'] = lifecycle_definition['properties']
               
        # add an attribute for the timeline
        if 'timeline' not in curr_lifecycle:
            curr_lifecycle['timeline'] = {}

        if 'ami_patch' not in curr_lifecycle['timeline']:
            timeline_url = self.awsapi_service.get_ami_patch_timeline_endpoint(lifecycle_definition['lifecycle_id'])
            curr_lifecycle['timeline']['ami_patch'] = timeline_url
        
        serialized_data = self.serializer.serialize(curr_lifecycle)
        
        # update item with new values
        self.dynamodb.put_item(
            TableName=self.AMI_LIFECYCLE_STATE_TABLENAME, 
            Item=serialized_data['M']
        )

        return curr_lifecycle
        
    
    def get_lifecycle_by_lifecycle_id(self, lifecycle_id: str) -> dict:
        try:
            response = self.dynamodb.get_item(
                TableName=self.AMI_LIFECYCLE_STATE_TABLENAME, 
                Key={'lifecycle_id': { 'S': lifecycle_id }}
            )
            
            serialized_data = {
                'M': response['Item']
            }

            return self.deserializer.deserialize(serialized_data)
        except Exception as e:
            logger.error(str(e))
            raise ClientError(str(e))


    def get_lifecycles(self) -> list:
        try:
            response = self.dynamodb.scan(
                TableName=self.AMI_LIFECYCLE_STATE_TABLENAME,
            )

            serialized_lifecycles = []

            for serialized_lifecycle in response['Items']:
                serialized_lifecycles.append({
                        'M': serialized_lifecycle
                    }
                )

            
            serialized_data = {
                'L': serialized_lifecycles
            }
            
            return self.deserializer.deserialize(serialized_data)
        except Exception as e:
            logger.error(str(e))
            raise ClientError(str(e))

    
    def update_event_result(self, lifecycle_id: str, event_result: dict) -> dict:
        try:
            lifecycle_obj = self.get_lifecycle_by_lifecycle_id(lifecycle_id)

            # remove the event in progress as we now have a result for that event
            if 'event_in_progress' in lifecycle_obj:
                del lifecycle_obj['event_in_progress']
            
            if "outputs_ami_creation" not in lifecycle_obj:
                lifecycle_obj["outputs_ami_creation"] = {}
                lifecycle_obj["outputs_ami_creation"]["events"] = []

            event_index = -1
            if "outputs_ami_creation" in lifecycle_obj:
                if 'events' in lifecycle_obj["outputs_ami_creation"]:
                    for idx, event in enumerate(lifecycle_obj["outputs_ami_creation"]["events"]):
                        if event['name'] == event_result['name']:
                            if event['status'] != self.constants_service.STATUS_COMPLETED:
                                event_index = idx
                                break

            if event_index == -1:
                lifecycle_obj["outputs_ami_creation"]["events"].append(event_result)
            else:
                lifecycle_obj["outputs_ami_creation"]["events"][event_index] = event_result
            
            serialized_data = self.serializer.serialize(lifecycle_obj)
        
            # update item with new values
            self.dynamodb.put_item(
                TableName=self.AMI_LIFECYCLE_STATE_TABLENAME, 
                Item=serialized_data['M']
            )

            return lifecycle_obj
        except Exception as e:
            logger.error(str(e))
            raise ClientError(str(e))


    def update_patch_event_result(self, lifecycle_id: str, event_result: dict) -> dict:
        try:
            lifecycle_obj = self.get_lifecycle_by_lifecycle_id(lifecycle_id)

            # remove the event in progress as we now have a result for that event
            if 'event_in_progress' in lifecycle_obj:
                del lifecycle_obj['event_in_progress']
            
            if "outputs_ami_patch" not in lifecycle_obj:
                lifecycle_obj["outputs_ami_patch"] = {}
                lifecycle_obj["outputs_ami_patch"]["patch_history"] = {}
                lifecycle_obj["outputs_ami_patch"]["patch_history"]["historical"] = []
                
            if "outputs_ami_patch" in lifecycle_obj:
                if 'patch_history' in lifecycle_obj["outputs_ami_patch"]:

                    # if we are dealing with an PATCH_AMI event then this becomes the current event
                    if event_result['name'] == self.constants_service.EVENT_PATCH_AMI:
                        # check if we have an existing current event then move it to historical
                        if 'current' in lifecycle_obj["outputs_ami_patch"]['patch_history']:
                            prev_current = lifecycle_obj["outputs_ami_patch"]['patch_history']['current']
                            lifecycle_obj["outputs_ami_patch"]["patch_history"]["historical"].append(prev_current)

                            # remove obsolete current object
                            del lifecycle_obj["outputs_ami_patch"]['patch_history']['current']
                        
                        # create a current patch output object
                        lifecycle_obj["outputs_ami_patch"]['patch_history']['current'] = {}
                        lifecycle_obj["outputs_ami_patch"]['patch_history']['current']['events'] = []
                        lifecycle_obj["outputs_ami_patch"]['patch_history']['current']['events'].append(event_result)

                        # add the ami ancestry to the event result
                        if 'properties' not in event_result:
                            event_result['properties'] = {}
                        
                        event_result['properties']['ami_ancestry'] = self.ami_details_service.get_ami_ancestry(lifecycle_obj)
                        
                    else:
                        # we are dealing with a patch testing event
                        event_match = False
                        if 'current' in lifecycle_obj["outputs_ami_patch"]['patch_history']:
                            if 'events' in lifecycle_obj["outputs_ami_patch"]['patch_history']['current']:
                                for event in lifecycle_obj["outputs_ami_patch"]['patch_history']['current']['events']:
                                    if event['name'] == event_result['name']:
                                        # update existing event
                                        event_match = True
                                        event = event_result

                        if event_match == False:
                            # add new event
                            lifecycle_obj["outputs_ami_patch"]['patch_history']['current']['events'].append(event_result)
                    
                
            serialized_data = self.serializer.serialize(lifecycle_obj)
        
            # update item with new values
            self.dynamodb.put_item(
                TableName=self.AMI_LIFECYCLE_STATE_TABLENAME, 
                Item=serialized_data['M']
            )

            return lifecycle_obj
        except Exception as e:
            logger.error(str(e))
            raise ClientError(str(e))


    def update_event_error(self, lifecycle_id: str, definition: dict) -> dict:
        try:
            lifecycle_obj = self.get_lifecycle_by_lifecycle_id(lifecycle_id)

            # update the event in progress with the error details
            if 'event_in_progress' in lifecycle_obj:
                lifecycle_obj['event_in_progress']['status'] = definition['status']
                lifecycle_obj['event_in_progress']['status_date'] = definition['status_date']
                lifecycle_obj['event_in_progress']['error_message'] = definition['error_message']
                lifecycle_obj['event_in_progress']['stack_trace'] = definition['stack_trace']
                if 'properties' in definition:
                    lifecycle_obj['event_in_progress']['properties'] = definition['properties']

                serialized_data = self.serializer.serialize(lifecycle_obj)
            
                # update item with new values
                self.dynamodb.put_item(
                    TableName=self.AMI_LIFECYCLE_STATE_TABLENAME, 
                    Item=serialized_data['M']
                )

            return lifecycle_obj
        except Exception as e:
            logger.error(str(e))
            raise ClientError(str(e))


    def update_event_in_progress(self, lifecycle_id: str, event_in_progress: dict) -> dict:
        try:
            lifecycle_obj = self.get_lifecycle_by_lifecycle_id(lifecycle_id)
            
            if "event_in_progress" not in lifecycle_obj:
                lifecycle_obj["event_in_progress"] = {}

            lifecycle_obj["event_in_progress"] = event_in_progress
            
            serialized_data = self.serializer.serialize(lifecycle_obj)
        
            # update item with new values
            self.dynamodb.put_item(
                TableName=self.AMI_LIFECYCLE_STATE_TABLENAME, 
                Item=serialized_data['M']
            )

            return lifecycle_obj
        except Exception as e:
            logger.error(str(e))
            raise ClientError(str(e))


    def get_ami_semver_by_stack_tag(self, stack_tag: str) -> str:
        try:
            response = self.dynamodb.get_item(
                TableName=self.AMI_SEMVER_SEED_TABLENAME, 
                Key={'stack_tag': { 'S': stack_tag }}
            )

            # it is an expected condition that a stack will not contain
            # a semver until an AMI is created for the first time.
            # When a semver is not available, we return the default semver seed
            if 'Item' not in response:
                return self.DEFAULT_AMI_SEMVER_SEED

            serialized_data = {
                'M': response['Item']
            }

            return self.deserializer.deserialize(serialized_data)['ami_semver']
        except Exception as e:
            logger.error(str(e))
            raise ClientError(str(e))


    def set_ami_semver_for_stack_tag(
            self, 
            stack_tag: str,
            ami_semver: str
        ) -> str:
        try:
            response = self.dynamodb.get_item(
                TableName=self.AMI_SEMVER_SEED_TABLENAME, 
                Key={'stack_tag': { 'S': stack_tag }}
            )

            # it is an expected condition that a stack will not contain
            # a semver until an AMI is created for the first time.
            # When a semver is not available, we return the default semver seed
            if 'Item' not in response:
                serialized_data = {
                    'M': {
                        'stack_tag': {
                            'S': stack_tag
                        },
                        'ami_semver': {
                            'S': ami_semver
                        }
                    }
                }
            else:
                serialized_data = {
                    'M': response['Item']
                }

            # deserialize to json
            semver_item = self.deserializer.deserialize(serialized_data)
            # update the semver on the json representation
            semver_item['ami_semver'] = ami_semver
            # serialize back to dynamodb representation
            serialized_data = self.serializer.serialize(semver_item)
        
            # update item with new values
            self.dynamodb.put_item(
                TableName=self.AMI_SEMVER_SEED_TABLENAME, 
                Item=serialized_data['M']
            )

            return self.deserializer.deserialize(serialized_data)
        except Exception as e:
            logger.error(str(e))
            raise ClientError(str(e))


    def update_ami_lookup(
            self, 
            ami_lookup_entries: list
        ) -> str:
        try:

            EVENT_SCORES = {
                self.constants_service.EVENT_BUILD_AMI: 1,
                self.constants_service.EVENT_PATCH_AMI: 1,
                self.constants_service.EVENT_SMOKE_TESTS_AMI_CREATE: 2,
                self.constants_service.EVENT_SMOKE_TESTS_AMI_PATCH: 2,
                self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_CREATE: 3,
                self.constants_service.EVENT_VULNERABILITY_SCANS_AMI_PATCH: 3,
                self.constants_service.EVENT_QA_CERTIFICATION_REQUEST: 4,
                self.constants_service.EVENT_QA_CERTIFICATION_RESPONSE: 5,
                self.constants_service.EVENT_MARK_FOR_PRODUCTION_CREATE: 6,
                self.constants_service.EVENT_MARK_FOR_PRODUCTION_PATCH: 6
            }

            for ami_lookup_entry in ami_lookup_entries:
                filter_expression = (
                    "ami_semver = :v2 and " +
                    "product_ver = :v3 and " +
                    "product_name = :v4 and " +
                    "lifecycle_type = :v5 and " +
                    "ami_id = :v6 and " +
                    "aws_region = :v7 and " +
                    "commit_ref = :v8"
                )
                response = self.dynamodb.query(
                    TableName=self.AMI_LOOKUP_TABLENAME,
                    IndexName="stack_tag_index",
                    KeyConditionExpression='stack_tag = :v1',
                    ExpressionAttributeValues={
                        ":v1": {
                            'S': ami_lookup_entry['stack_tag']
                        },
                        ":v2": {
                            'S': ami_lookup_entry['ami_semver']
                        },
                        ":v3": {
                            'S': ami_lookup_entry['product_ver']
                        },
                        ":v4": {
                            'S': ami_lookup_entry['product_name']
                        },
                        ":v5": {
                            'S': ami_lookup_entry['lifecycle_type']
                        },
                        ":v6": {
                            'S':  ami_lookup_entry['ami_id']
                        },
                        ":v7": {
                            'S':  ami_lookup_entry['aws_region']
                        },
                        ":v8": {
                            'S':  ami_lookup_entry['commit_ref']
                        }
                    },
                    FilterExpression=filter_expression
                )

                if 'Items' in response:
                    if len(response['Items']) == 0:
                        # no match so create a new lookup entry
                        ami_lookup_entry = {
                            "lookup_id": str(uuid.uuid4()),
                            "last_modified": datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                            "stack_tag": ami_lookup_entry['stack_tag'],
                            "ami_id": ami_lookup_entry['ami_id'],
                            "ami_semver": ami_lookup_entry['ami_semver'],
                            "product_ver": ami_lookup_entry['product_ver'],
                            "product_name": ami_lookup_entry['product_name'],
                            "lifecycle_type": ami_lookup_entry['lifecycle_type'],
                            "lifecycle_event": ami_lookup_entry['lifecycle_event'],
                            "lifecycle_score": EVENT_SCORES[ami_lookup_entry['lifecycle_event']],
                            "lifecycle_id": ami_lookup_entry['lifecycle_id'],
                            "aws_region": ami_lookup_entry['aws_region'],
                            "commit_ref": ami_lookup_entry['commit_ref']
                        }
                        serialized_data = self.serializer.serialize(ami_lookup_entry)
                    else:
                        # we have a match so update existing lookup
                        _serialized_data = {
                            'M': response['Items'][0]
                        }
                        deserialized_data = self.deserializer.deserialize(_serialized_data)
                        deserialized_data['lifecycle_event'] = ami_lookup_entry['lifecycle_event']
                        deserialized_data['lifecycle_score'] = EVENT_SCORES[ami_lookup_entry['lifecycle_event']]
                        deserialized_data['last_modified'] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
                        serialized_data = self.serializer.serialize(deserialized_data)

                    # update item with new values
                    self.dynamodb.put_item(
                        TableName=self.AMI_LOOKUP_TABLENAME, 
                        Item=serialized_data['M']
                    )

        except Exception as e:
            logger.error(str(e))
            raise ClientError(str(e))


    def get_latest_semver_by_stack_tag(self, stack_tag: str) -> str:
        def _semver_compare(x, y):
            return semver.compare(x['ami_semver'], y['ami_semver'])
        
        try:
            response = self.dynamodb.query(
                TableName=self.AMI_LOOKUP_TABLENAME,
                IndexName="stack_tag_index",
                KeyConditionExpression='stack_tag = :v1',
                ExpressionAttributeValues={
                    ":v1": {
                        'S': stack_tag
                    }
                }
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
                    sorted_list = sorted(deserialized_data, key=functools.cmp_to_key(_semver_compare), reverse=True)
                    return sorted_list[0]['ami_semver']

            return self.DEFAULT_AMI_SEMVER_SEED

        except Exception as e:
            logger.error(str(e))
            raise ClientError(str(e))
