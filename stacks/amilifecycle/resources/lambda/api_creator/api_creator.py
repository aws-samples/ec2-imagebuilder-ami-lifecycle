#!/usr/bin/env python

"""
    api_creator.py: 
    Cloudformation custom resource lambda handler which performs the following tasks:
    *   injects lambda functions arns (created during CDK deployment) into the 
        OpenAPI 3 spec file (api_definition/ami-orchestrator-api.yaml)
    *   deploys or updates the API Gateway stage using the OpenAPI 3 spec file (api_definition/ami-orchestrator-api.yaml)
    *   deletes the API Gateway stage (if the Cloudformation operation is delete)
"""

import json
import logging

import boto3

# set logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

client = boto3.client('apigatewayv2')

def replace_placeholders(template_file: str, substitutions: dict) -> str:
    import re

    def from_dict(dct):
        def lookup(match):
            key = match.group(1)
            return dct.get(key, f'<{key} not found>')
        return lookup

    with open (template_file, "r") as template_file:
        template_data = template_file.read()

    # perform the subsitutions, looking for placeholders @@PLACEHOLDER@@
    api_template = re.sub('@@(.*?)@@', from_dict(substitutions), template_data)

    return api_template


def get_api_by_name(api_name: str) -> str:
    get_apis = client.get_apis()
    for api in get_apis['Items']:
        if api['Name'] == api_name:
            return api['ApiId']

    return None


def create_api(api_template:str) -> str:
    api_response = client.import_api(
        Body=api_template,
        FailOnWarnings=True
    )

    return api_response['ApiEndpoint'], api_response['ApiId']


def update_api(api_template: str, api_name:str) -> str:
    
    api_id = get_api_by_name(api_name)

    if api_id is not None:
        api_response = client.reimport_api(
            ApiId=api_id,
            Body=api_template,
            FailOnWarnings=True
        )
        return api_response['ApiEndpoint'], api_response['ApiId']


def delete_api(api_name: str) -> None:
    if get_api_by_name(api_name) is not None:
        response = client.delete_api(
            ApiId=get_api_by_name(api_name)
        )


def deploy_api(
        api_id: str, 
        api_stage_name: str,
        api_access_logs_arn: str,
        throttling_burst_limit: int, 
        throttling_rate_limit: int
    ) -> None:
    client.create_stage(
        AccessLogSettings={
            'DestinationArn': api_access_logs_arn,
            'Format': '$context.identity.sourceIp - - [$context.requestTime] "$context.httpMethod $context.routeKey $context.protocol" $context.status $context.responseLength $context.requestId $context.integrationErrorMessage'
        },
        ApiId=api_id,
        StageName=api_stage_name,
        AutoDeploy=True,
        DefaultRouteSettings={
            'DetailedMetricsEnabled': True,
            'ThrottlingBurstLimit':throttling_burst_limit,
            'ThrottlingRateLimit': throttling_rate_limit
        }
    )


def delete_api_deployment(api_id: str, api_stage_name: str) -> None:
    try:
        client.get_stage(
            ApiId=api_id,
            StageName=api_stage_name
        )

        client.delete_stage(
            ApiId=api_id,
            StageName=api_stage_name
        )
    except client.exceptions.NotFoundException as e:
        logger.error(f"Stage name: {api_stage_name} for api id: {api_id} was not found during stage deletion. This is an expected error condition and is handled in code.")
    except Exception as e:
        raise ValueError(f"Unexpected error encountered during api deployment deletion: {str(e)}")


def lambda_handler(event, context):
    
    # print the event details
    logger.debug(json.dumps(event, indent=2))

    props = event['ResourceProperties']
    api_get_status_by_lifecycle_id_lambda = props['ApiGetStatuByLifecycleIdLambda']
    api_gateway_access_log_group_arn = props['ApiGatewayAccessLogsLogGroupArn']
    api_create_lifecycle_lambda = props['ApiCreateLifecycleLambda']
    api_create_update_lifecycle_lambda = props['ApiCreateUpdateLifecycleLambda']
    api_get_status_by_stack_tag_lambda = props['ApiGetStatusByStackTagLambda']
    api_create_qa_certify_response_lambda = props['ApiCreateQACertifyResponseLambda']
    api_create_mark_for_production_lambda = props['ApiCreateMarkForProductionLambda']
    api_create_timeline_lambda = props['ApiCreateTimelineLambda']
    api_patch_lifecycle_lambda = props['ApiPatchLifecycleLambda']
    api_patch_update_lifecycle_lambda = props['ApiPatchUpdateLifecycleLambda']
    api_patch_timeline_lambda = props['ApiPatchTimelineLambda']
    api_patch_mark_for_production_lambda = props['ApiPatchMarkForProductionLambda']
    api_name = props['ApiName']
    api_stage_name = props['ApiStageName']
    throttling_burst_limit = int(props['ThrottlingBurstLimit'])
    throttling_rate_limit = int(props['ThrottlingRateLimit'])
    aws_region = props['AwsRegion']

    lambda_substitutions = {
        "API_NAME": api_name,
        "API_GET_STATUS_BY_LIFECYCLEID_LAMBDA": f"arn:aws:apigateway:{aws_region}:lambda:path/2015-03-31/functions/{api_get_status_by_lifecycle_id_lambda}/invocations",
        "API_LIFECYCLE_CREATE_LAMBDA": f"arn:aws:apigateway:{aws_region}:lambda:path/2015-03-31/functions/{api_create_lifecycle_lambda}/invocations",
        "API_LIFECYCLE_CREATE_UPDATE_LAMBDA": f"arn:aws:apigateway:{aws_region}:lambda:path/2015-03-31/functions/{api_create_update_lifecycle_lambda}/invocations",
        "API_GET_STATUS_BY_STACKTAG_LAMBDA": f"arn:aws:apigateway:{aws_region}:lambda:path/2015-03-31/functions/{api_get_status_by_stack_tag_lambda}/invocations",
        "API_LIFECYCLE_QA_CERTIFICATION_LAMBDA": f"arn:aws:apigateway:{aws_region}:lambda:path/2015-03-31/functions/{api_create_qa_certify_response_lambda}/invocations",
        "API_CREATION_MARK_FOR_PRODUCTION_APPROVAL_LAMBDA": f"arn:aws:apigateway:{aws_region}:lambda:path/2015-03-31/functions/{api_create_mark_for_production_lambda}/invocations",
        "API_PATCH_MARK_FOR_PRODUCTION_APPROVAL_LAMBDA": f"arn:aws:apigateway:{aws_region}:lambda:path/2015-03-31/functions/{api_patch_mark_for_production_lambda}/invocations",
        "API_GET_TIMELINE_BY_LIFECYCLEID_LAMBDA": f"arn:aws:apigateway:{aws_region}:lambda:path/2015-03-31/functions/{api_create_timeline_lambda}/invocations",
        "API_LIFECYCLE_PATCH_LAMBDA": f"arn:aws:apigateway:{aws_region}:lambda:path/2015-03-31/functions/{api_patch_lifecycle_lambda}/invocations",
        "API_LIFECYCLE_PATCH_UPDATE_LAMBDA": f"arn:aws:apigateway:{aws_region}:lambda:path/2015-03-31/functions/{api_patch_update_lifecycle_lambda}/invocations",
        "API_GET_PATCH_TIMELINE_BY_LIFECYCLEID_LAMBDA": f"arn:aws:apigateway:{aws_region}:lambda:path/2015-03-31/functions/{api_patch_timeline_lambda}/invocations"
    }

    api_template = replace_placeholders("api_definition/ami-orchestrator-api.yaml", lambda_substitutions)

    if event['RequestType'] != 'Delete':

        if get_api_by_name(api_name) is None:

            logger.debug("Creating API")

            api_endpoint, api_id = create_api(api_template)

            deploy_api(api_id, api_stage_name, api_gateway_access_log_group_arn, throttling_burst_limit, throttling_rate_limit)

            output = {
                'PhysicalResourceId': f"generated-api",
                'Data': {
                    'ApiEndpoint': api_endpoint,
                    'ApiId': api_id,
                    'ApiStageName': api_stage_name
                }
            }
            
            return output

        else:

            logger.debug("Updating API")

            api_endpoint, api_id = update_api(api_template, api_name)

            # delete and redeploy the stage after updating the api definition
            delete_api_deployment(api_id, api_stage_name)
            deploy_api(api_id, api_stage_name, api_gateway_access_log_group_arn, throttling_burst_limit, throttling_rate_limit)

            output = {
                'PhysicalResourceId': f"generated-api",
                'Data': {
                    'ApiEndpoint': api_endpoint,
                    'ApiId': api_id,
                    'ApiStageName': api_stage_name
                }
            }
        
        return output

    if event['RequestType'] == 'Delete':

        logger.debug("Deleting API")

        if get_api_by_name(api_name) is not None:
            delete_api(api_name)

        output = {
            'PhysicalResourceId': f"generated-api",
            'Data': {
                'ApiEndpoint': "Deleted",
                'ApiId': "Deleted",
                'ApiStageName': "Deleted"
            }
        }
        logger.info(output)
        
        return output
