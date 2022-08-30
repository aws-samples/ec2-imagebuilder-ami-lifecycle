#!/usr/bin/env python

"""
    ami_lifecycle.py:
    AMI Lifecycle CDK stack which:
    * creates the AWS infrastructue of the Orchestrator API and AMI Lifecycle Step Functions
    * deploys the Orchestrator API specification to API Gateway
    * creates and persists the Orchestrator API keys to AWS Secrets Manager
"""

import json
import os
import random
import string
import subprocess

from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as events_targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_lambda
from aws_cdk import aws_lambda_event_sources as event_sources
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_assets as assets
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as sns_subscriptions
from aws_cdk import aws_sqs as sqs
from aws_cdk import aws_stepfunctions as stepfunctions
from aws_cdk import aws_stepfunctions_tasks as stepfunctions_tasks
from aws_cdk import core, custom_resources
from utils.CdkConstants import CdkConstants
from utils.CdkUtils import CdkUtils
from utils.IAMPrincipals import IAMPrincipals


class AmiLifecycleStack(core.Stack):
    """
        AMI Lifecycle CDK stack which:
        * creates the AWS infrastructue of the Orchestrator API and AMI Lifecycle Step Functions
        * deploys the Orchestrator API specification to API Gateway
        * creates and persists the Orchestrator API keys to AWS Secrets Manager
    """

    def __init__(
            self, 
            scope: core.Construct, 
            id: str,
            stack_outputs: dict,
            **kwargs
        ) -> None:
        super().__init__(scope, id, **kwargs)

        self.config = CdkUtils.get_project_settings()

        self.vpc = stack_outputs['vpc']
        self.imagebuilder_instance_profile_arn = stack_outputs['imagebuilder_instance_profile_arn']
        self.imagebuilder_instance_profile_name = stack_outputs['imagebuilder_instance_profile_name']
        self.imagebuilder_subnet_id = stack_outputs['imagebuilder_subnet_id']
        self.imagebuilder_topic_arn = stack_outputs['imagebuilder_topic_arn']
        self.imagebuilder_security_group = stack_outputs['imagebuilder_security_group']
        self.imagebuilder_kms_key_arn = stack_outputs['kms_key_arn']
        self.vmdk_export_bucket_arn = stack_outputs['vmdk_export_bucket_arn']

        ##########################################################
        ##########################################################
        ##########################################################
        # <START> AMI Orchestrator
        ##########################################################
        ##########################################################
        ##########################################################

        ##########################################################
        # <START> Create DynamoDB table
        ##########################################################

        self.ami_orchestrator_key = kms.Key(
            self,
            id=f'AmiOrchestrator',
            enable_key_rotation=True,
            enabled=True,
            description="Ami Orchestrator KMS Key",
            removal_policy=core.RemovalPolicy.DESTROY
        )

        self.ami_lifecycle_table = dynamodb.Table(
            self,
            "AmiOrchestratorTable",
            partition_key=dynamodb.Attribute(name='lifecycle_id', type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=core.RemovalPolicy.DESTROY,
            point_in_time_recovery=True,
            encryption=dynamodb.TableEncryption.DEFAULT
        )

        self.ami_lifecycle_table.add_global_secondary_index(
            index_name="stack_tag_index",
            partition_key=dynamodb.Attribute(name='stack_tag', type=dynamodb.AttributeType.STRING)
        )

        self.ami_lookup_table = dynamodb.Table(
            self,
            "AmiLookupTable",
            partition_key=dynamodb.Attribute(name='lookup_id', type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=core.RemovalPolicy.DESTROY,
            point_in_time_recovery=True,
            encryption=dynamodb.TableEncryption.DEFAULT
        )

        self.ami_lookup_table.add_global_secondary_index(
            index_name="stack_tag_index",
            partition_key=dynamodb.Attribute(name='stack_tag', type=dynamodb.AttributeType.STRING)
        )

        self.ami_semver_seed_table = dynamodb.Table(
            self,
            "AmiSemverSeedTable",
            partition_key=dynamodb.Attribute(name='stack_tag', type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=core.RemovalPolicy.DESTROY,
            point_in_time_recovery=True,
            encryption=dynamodb.TableEncryption.DEFAULT
        )

        self.ami_semver_seed_table.add_global_secondary_index(
            index_name="stack_tag_index",
            partition_key=dynamodb.Attribute(name='stack_tag', type=dynamodb.AttributeType.STRING)
        )

        self.ami_orchestrator_key.grant_encrypt_decrypt(IAMPrincipals.DYNAMODB.value)

        ##########################################################
        # </END> Create DynamoDB table
        ##########################################################


        ##########################################################
        # <START> Create SNS topic for notifications
        ##########################################################

        self.notification_topic = sns.Topic(
            self, "AmiOrchestratorTopic",
            master_key=self.ami_orchestrator_key
        )

        self.reconciliation_topic = sns.Topic(
            self, f"AmiOrchestratorReconcilerTopic",
            master_key=self.ami_orchestrator_key
        )

        self.ami_orchestrator_key.grant_encrypt_decrypt(IAMPrincipals.SNS.value)

        ##########################################################
        # </END> Create SNS topic for notifications
        ##########################################################

        ##########################################################
        # <START> Create SQS queues for receivers
        ##########################################################

        self.ami_creation_receiver_queue = sqs.Queue(
            self, 
            "AmiCreationReceiverQueue",
            encryption=sqs.QueueEncryption.KMS_MANAGED,
            visibility_timeout=core.Duration.hours(1)
        )

        self.ami_creation_receiver_queue.grant_send_messages(IAMPrincipals.STEP_FUNCTIONS.value)

        self.ami_patch_receiver_queue = sqs.Queue(
            self, 
            "AmiPatchReceiverQueue",
            encryption=sqs.QueueEncryption.KMS_MANAGED,
            visibility_timeout=core.Duration.hours(1)
        )

        self.ami_patch_receiver_queue.grant_send_messages(IAMPrincipals.STEP_FUNCTIONS.value)

        self.ami_error_receiver_queue = sqs.Queue(
            self, 
            "AmiErrorReceiverQueue",
            encryption=sqs.QueueEncryption.KMS_MANAGED,
            visibility_timeout=core.Duration.hours(1)
        )

        self.ami_error_receiver_queue.grant_send_messages(IAMPrincipals.STEP_FUNCTIONS.value)

        ##########################################################
        # </END> Create SQS topics for receivers
        ##########################################################


        ##########################################################
        # <START> Create S3 Bucket for AMI Patch components
        ##########################################################
        self.ami_patch_component_bucket = s3.Bucket(
            self, 
            "AmiPatchComponentS3Bucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            removal_policy=core.RemovalPolicy.DESTROY,
            public_read_access=False,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True
        )
        ##########################################################
        # </END> Create S3 Bucket for AMI Patch components
        ##########################################################

        ##########################################################
        # <START> Log groups
        ##########################################################

        # create log group for API Gateway access logs with 14 day retention period
        api_gateway_access_log_group = logs.LogGroup(
            self, 
            'amiOrchestratorApiGatewayLogGroup',
            log_group_name='/aws/vendedlogs/amiOrchestratorApiGatewayAccessLogs',
            removal_policy=core.RemovalPolicy.DESTROY,
            retention=logs.RetentionDays.TWO_WEEKS
        )

        # create log group for Orchestrator Event Notifications
        event_notifications_log_group = logs.LogGroup(
            self, 
            'amiOrchestratorEventNotificationsLogGroup',
            log_group_name='/ami-lifecycles/event-notifications',
            removal_policy=core.RemovalPolicy.DESTROY,
            retention=logs.RetentionDays.TWO_WEEKS
        )

        # create log group for Orchestrator Reconciler Notifications
        reconciler_notifications_log_group = logs.LogGroup(
            self, 
            'amiOrchestratorReconcilerNotificationsLogGroup',
            log_group_name='/ami-lifecycles/reconciler-notifications',
            removal_policy=core.RemovalPolicy.DESTROY,
            retention=logs.RetentionDays.TWO_WEEKS
        )

        ##########################################################
        # </END> Log groups
        ##########################################################


        ##########################################################
        # <START> Create Event Notification Lambda function
        ##########################################################

        event_notification_lambda_role = iam.Role(
            scope=self,
            id=f"AmiLcEventNotificationsLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ]
        )
        
        event_notification_lambda_role.add_to_policy(self.get_cloudwatch_policy())
        
        self.event_notification_lambda = aws_lambda.Function(
            scope=self,
            id="AmiLcEventNotificationsLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/event_notifications"),
            handler="event_notifications.lambda_handler",
            role=event_notification_lambda_role,
            environment={
                "LOG_GROUP_NAME": event_notifications_log_group.log_group_name
            },
            timeout=core.Duration.seconds(30),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        self.ami_orchestrator_key.grant_encrypt_decrypt(self.event_notification_lambda)

        self.notification_topic.add_subscription(
            sns_subscriptions.LambdaSubscription(
                fn=self.event_notification_lambda
            )
        )

        # RECONCILER NOTIFICATIONS
        reconciler_notification_lambda_role = iam.Role(
            scope=self,
            id="AmiLcReconcilerNotificationsLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ]
        )
        
        reconciler_notification_lambda_role.add_to_policy(self.get_cloudwatch_policy())
        
        self.reconciler_notification_lambda = aws_lambda.Function(
            scope=self,
            id="AmiLcReconcilerNotificationsLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/event_notifications"),
            handler="reconciler_notifications.lambda_handler",
            role=reconciler_notification_lambda_role,
            environment={
                "LOG_GROUP_NAME": reconciler_notifications_log_group.log_group_name
            },
            timeout=core.Duration.seconds(30),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        self.ami_orchestrator_key.grant_encrypt_decrypt(self.reconciler_notification_lambda)

        self.reconciliation_topic.add_subscription(
            sns_subscriptions.LambdaSubscription(
                fn=self.reconciler_notification_lambda
            )
        )

        
        ##########################################################
        # </END> Create Event Notification Lambda functions
        ##########################################################

        ##########################################################
        # <START> Define API lambda layers
        ##########################################################

        # https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html#configuration-layers-path
        __orchestrator_deps_layer_dir = f"{os.path.dirname(__file__)}/resources/lambda/layers/ami_orchestrator_deps"
        __orchestrator_deps_layer_output_dir = f"{os.path.dirname(__file__)}/resources/lambda/layers/ami_orchestrator_deps/.lambda_dependencies"

        subprocess.check_call(
            f"rm -fr {__orchestrator_deps_layer_output_dir}".split()
        )
        subprocess.check_call(
            f"pip install --upgrade pip".split()
        )
        subprocess.check_call(
            f"pip install -r {__orchestrator_deps_layer_dir}/requirements.txt -t {__orchestrator_deps_layer_output_dir}/python".split()
        )
        self.ami_orchestrator_deps_layer = aws_lambda.LayerVersion(
            self,
            "amiOrchestratorDependenciesLayer",
            code=aws_lambda.Code.from_asset(__orchestrator_deps_layer_output_dir),
            description="AMI Orchestrator 3rd party dependencies",
            compatible_runtimes=[
                aws_lambda.Runtime.PYTHON_3_9
            ]
        )

        ##########################################################
        # </END> Define API lambda layers
        ##########################################################

        ##########################################################
        # <START> Create API Lambda functions
        ##########################################################

        ami_lifecycle_get_status_by_lifecycle_id = self.get_ami_lifecycle_get_status_by_lifecycle_id_lambda()
        ami_lifecycle_get_status_by_stack_tag = self.get_ami_lifecycle_get_status_by_stack_tag_lambda()
        ami_creation_lifecycle_post_lambda = self.get_ami_creation_lifecycle_post_lambda()
        ami_creation_lifecycle_put_lambda = self.get_ami_creation_lifecycle_put_lambda()
        ami_creation_qa_certify_lambda = self.get_ami_creation_qa_certify_lambda()
        ami_creation_mark_for_production_lambda= self.get_ami_creation_mark_for_production_lambda()
        ami_creation_timeline_lambda = self.get_ami_creation_timeline_lambda()
        ami_creation_receiver_lambda = self.get_ami_creation_receiver_lambda()
        ami_patch_lifecycle_post_lambda = self.get_ami_patch_lifecycle_post_lambda()
        ami_patch_lifecycle_put_lambda = self.get_ami_patch_lifecycle_put_lambda()
        ami_patch_timeline_lambda = self.get_ami_patch_timeline_lambda()
        ami_patch_mark_for_production_lambda= self.get_ami_patch_mark_for_production_lambda()
        ami_patch_receiver_lambda = self.get_ami_patch_receiver_lambda()
        ami_error_receiver_lambda = self.get_ami_error_receiver_lambda()
        ami_reconciler_lambda = self.get_reconciler_lambda()

        # give the relevant lambda function access to orchestrator key
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_lifecycle_get_status_by_lifecycle_id)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_creation_lifecycle_post_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_creation_lifecycle_put_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_creation_qa_certify_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_creation_mark_for_production_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_creation_timeline_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_creation_receiver_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_patch_receiver_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_error_receiver_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_lifecycle_get_status_by_stack_tag)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_patch_lifecycle_post_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_patch_lifecycle_put_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_patch_timeline_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_patch_mark_for_production_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_reconciler_lambda)

        # give access to the patch component bucket
        self.ami_patch_component_bucket.grant_read_write(ami_patch_lifecycle_post_lambda)

        # give the receiver lambdas access to the SQS queues
        self.ami_creation_receiver_queue.grant_consume_messages(ami_creation_receiver_lambda)
        ami_creation_receiver_lambda.add_event_source(
            event_sources.SqsEventSource(self.ami_creation_receiver_queue)
        )

        self.ami_patch_receiver_queue.grant_consume_messages(ami_patch_receiver_lambda)
        ami_patch_receiver_lambda.add_event_source(
            event_sources.SqsEventSource(self.ami_patch_receiver_queue)
        )

        self.ami_error_receiver_queue.grant_consume_messages(ami_error_receiver_lambda)
        ami_error_receiver_lambda.add_event_source(
            event_sources.SqsEventSource(self.ami_error_receiver_queue)
        )

        # schedule the reconciler
        # cron syntax describe in the documentation referenced below
        # https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html
        ami_reconciler_event_rule = events.Rule(
            self,
            "AmiLcReconcilerEventRule",
            schedule=events.Schedule.expression(self.config['amiLifecycle']['dbToTagReconcilerCronExpr'])
        )

        ami_reconciler_event_rule.add_target(
            events_targets.LambdaFunction(
                    ami_reconciler_lambda
                )
            )

        ##########################################################
        # </END> Create API Lambda functions
        ##########################################################

        ##########################################################
        # <START> Create API Creator Custom Resource
        ##########################################################

        # Create a role for the api creator lambda function
        apicreator_lambda_role = iam.Role(
            scope=self,
            id=f"ApiCreateLmbRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ]
        )

        apicreator_lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=[
                    "arn:aws:apigateway:*::/apis/*",
                    "arn:aws:apigateway:*::/apis"
                ],
                actions=[
                    "apigateway:DELETE",
                    "apigateway:PUT",
                    "apigateway:PATCH",
                    "apigateway:POST",
                    "apigateway:GET"
                ]
            )
        )

        apicreator_lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=["*"],
                actions=[
                    "logs:*"
                ]
            )
        )

        apicreator_lambda = aws_lambda.Function(
            scope=self,
            id="ApiCreateLmb",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/api_creator"),
            handler="api_creator.lambda_handler",
            role=apicreator_lambda_role,
            layers=[self.ami_orchestrator_deps_layer],
            timeout=core.Duration.seconds(30),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        # Provider that invokes the api creator lambda function
        apicreator_provider = custom_resources.Provider(
            self,
            f'ApiCreateCusResPro',
            on_event_handler=apicreator_lambda
        )

        # The custom resource that uses the api creator provider to supply values
        apicreator_custom_resource = core.CustomResource(
            self,
            f'ApiCreateCusRes',
            service_token=apicreator_provider.service_token,
            properties={
                'AwsRegion': self.region,
                'ApiGatewayAccessLogsLogGroupArn': api_gateway_access_log_group.log_group_arn,
                'ApiGetStatuByLifecycleIdLambda': ami_lifecycle_get_status_by_lifecycle_id.function_arn,
                'ApiCreateLifecycleLambda': ami_creation_lifecycle_post_lambda.function_arn,
                'ApiCreateUpdateLifecycleLambda': ami_creation_lifecycle_put_lambda.function_arn,
                'ApiGetStatusByStackTagLambda': ami_lifecycle_get_status_by_stack_tag.function_arn,
                'ApiCreateQACertifyResponseLambda': ami_creation_qa_certify_lambda.function_arn,
                'ApiCreateMarkForProductionLambda': ami_creation_mark_for_production_lambda.function_arn,
                'ApiCreateTimelineLambda': ami_creation_timeline_lambda.function_arn,
                'ApiPatchLifecycleLambda': ami_patch_lifecycle_post_lambda.function_arn,
                'ApiPatchUpdateLifecycleLambda': ami_patch_lifecycle_put_lambda.function_arn,
                'ApiPatchTimelineLambda': ami_patch_timeline_lambda.function_arn,
                'ApiPatchMarkForProductionLambda': ami_patch_mark_for_production_lambda.function_arn,
                'ApiName': f"{self.config['amiLifecycle']['api']['apiName']}",
                'ApiStageName': self.config['amiLifecycle']['api']['apiStageName'],
                'ThrottlingBurstLimit': self.config['amiLifecycle']['api']['throttlingBurstLimit'],
                'ThrottlingRateLimit': self.config['amiLifecycle']['api']['throttlingRateLimit']
            }
        )

        ##########################################################
        # </END> Create API Creator Custom Resource
        ##########################################################

        ##########################################################
        # <START> Create Secrets Manager API Keys Custom Resource
        ##########################################################

        # Create a role for the secrets manager lambda function
        secrets_manager_lambda_role = iam.Role(
            scope=self,
            id=f"amiLifecycleSecretsManagerLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ]
        )

        api_keys_internal = self.config['amiLifecycle']['api']['security']['api_keys']['internal']
        api_keys_external = self.config['amiLifecycle']['api']['security']['api_keys']['external']

        # add permissions for Secrets Manager
        secrets_manager_lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=[
                    f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:/ami-lifecycle/api-keys/{api_keys_internal['ami_creation_post_secret_name']}*",
                    f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:/ami-lifecycle/api-keys/{api_keys_internal['ami_creation_put_secret_name']}*",
                    f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:/ami-lifecycle/api-keys/{api_keys_internal['ami_creation_status_secret_name']}*",
                    f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:/ami-lifecycle/api-keys/{api_keys_internal['ami_creation_timeline_secret_name']}*",
                    f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:/ami-lifecycle/api-keys/{api_keys_internal['ami_creation_receiver_secret_name']}*",
                    f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:/ami-lifecycle/api-keys/{api_keys_internal['ami_patch_receiver_secret_name']}*",
                    f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:/ami-lifecycle/api-keys/{api_keys_internal['ami_error_receiver_secret_name']}*",
                    f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:/ami-lifecycle/api-keys/{api_keys_external['ami_creation_qa_certification_secret_name']}*",
                    f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:/ami-lifecycle/api-keys/{api_keys_external['ami_creation_mark_for_production_secret_name']}*",
                    f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:/ami-lifecycle/api-keys/{api_keys_external['ami_patch_mark_for_production_secret_name']}*",
                    f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:/ami-lifecycle/api-keys/{api_keys_internal['ami_patch_post_secret_name']}*",
                    f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:/ami-lifecycle/api-keys/{api_keys_internal['ami_patch_put_secret_name']}*",
                    f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:/ami-lifecycle/api-keys/{api_keys_internal['ami_patch_timeline_secret_name']}*",
                ],
                actions=[
                    "secretsmanager:PutSecretValue",
                    "secretsmanager:CreateSecret",
                    "secretsmanager:DeleteSecret"
                ]
            )
        )

        secrets_manager_lambda = aws_lambda.Function(
            scope=self,
            id="amiLifecycleSecretsManagerLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/api_key_generator"),
            handler="api_key_generator.lambda_handler",
            role=secrets_manager_lambda_role,
            timeout=core.Duration.seconds(30),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        # Provider that invokes the secrets_manager lambda function
        secrets_manager_provider = custom_resources.Provider(
            self,
            f'amiLifecycleSecretsManagerCRProvider',
            on_event_handler=secrets_manager_lambda
        )

        # The custom resource that uses the secrets manager provider to supply value
        secrets_manager_custom_resource = core.CustomResource(
            self,
            'amiLifecycleSecretsManagerCR',
            service_token=secrets_manager_provider.service_token,
            properties = {
                'AMI_CREATION_POST_SECRET_NAME': api_keys_internal['ami_creation_post_secret_name'],
                'AMI_CREATION_PUT_SECRET_NAME': api_keys_internal['ami_creation_put_secret_name'],
                'AMI_CREATION_STATUS_SECRET_NAME': api_keys_internal['ami_creation_status_secret_name'],
                'AMI_CREATION_TIMELINE_SECRET_NAME': api_keys_internal['ami_creation_timeline_secret_name'],
                'AMI_CREATION_QA_CERTIFICATION_SECRET_NAME': api_keys_external['ami_creation_qa_certification_secret_name'],
                'AMI_CREATION_MARK_FOR_PRODUCTION_SECRET_NAME': api_keys_external['ami_creation_mark_for_production_secret_name'],
                'AMI_PATCH_MARK_FOR_PRODUCTION_SECRET_NAME': api_keys_external['ami_patch_mark_for_production_secret_name'],
                'AMI_CREATION_RECEIVER_SECRET_NAME': api_keys_internal['ami_creation_receiver_secret_name'],
                'AMI_PATCH_RECEIVER_SECRET_NAME': api_keys_internal['ami_patch_receiver_secret_name'],
                'AMI_ERROR_RECEIVER_SECRET_NAME': api_keys_internal['ami_error_receiver_secret_name'],
                'AMI_PATCH_POST_SECRET_NAME': api_keys_internal['ami_patch_post_secret_name'],
                'AMI_PATCH_PUT_SECRET_NAME': api_keys_internal['ami_patch_put_secret_name'],
                'AMI_PATCH_TIMELINE_SECRET_NAME': api_keys_internal['ami_patch_timeline_secret_name']
            }
        )

        # The result obtained from the output of custom resource
        generated_api_keys = core.CustomResource.get_att_string(secrets_manager_custom_resource, attribute_name=f"secrets-manager-api-keys")

        ##########################################################
        # </END> Create Secrets Manager API Keys Custom Resource
        ##########################################################


        ##########################################################
        # <START> Create AWS API Gateway permissions
        ##########################################################

        apigateway_id = core.CustomResource.get_att_string(apicreator_custom_resource, attribute_name='ApiId')
        apigateway_endpoint = core.CustomResource.get_att_string(apicreator_custom_resource, attribute_name='ApiEndpoint')
        apigateway_stagename = core.CustomResource.get_att_string(apicreator_custom_resource, attribute_name='ApiStageName')

        http_api_arn = (
            f"arn:{self.partition}:execute-api:"
            f"{self.region}:{self.account}:"
            f"{apigateway_id}/*/*/*"
        )

        # grant HttpApi permission to invoke api lambda function
        ami_lifecycle_get_status_by_lifecycle_id.add_permission(
            f"Invoke By Orchestrator Gateway Permission",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            action="lambda:InvokeFunction",
            source_arn=http_api_arn
        )

        ami_lifecycle_get_status_by_stack_tag.add_permission(
            f"Invoke By Orchestrator Gateway Permission",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            action="lambda:InvokeFunction",
            source_arn=http_api_arn
        )

        ami_creation_lifecycle_post_lambda.add_permission(
            f"Invoke By Orchestrator Gateway Permission",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            action="lambda:InvokeFunction",
            source_arn=http_api_arn
        )

        ami_creation_lifecycle_put_lambda.add_permission(
            f"Invoke By Orchestrator Gateway Permission",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            action="lambda:InvokeFunction",
            source_arn=http_api_arn
        )

        ami_creation_qa_certify_lambda.add_permission(
            f"Invoke By Orchestrator Gateway Permission",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            action="lambda:InvokeFunction",
            source_arn=http_api_arn
        )

        ami_creation_mark_for_production_lambda.add_permission(
            f"Invoke By Orchestrator Gateway Permission",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            action="lambda:InvokeFunction",
            source_arn=http_api_arn
        )

        ami_creation_timeline_lambda.add_permission(
            f"Invoke By Orchestrator Gateway Permission",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            action="lambda:InvokeFunction",
            source_arn=http_api_arn
        )

        ami_patch_lifecycle_post_lambda.add_permission(
            f"Invoke By Orchestrator Gateway Permission",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            action="lambda:InvokeFunction",
            source_arn=http_api_arn
        )

        ami_patch_lifecycle_put_lambda.add_permission(
            f"Invoke By Orchestrator Gateway Permission",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            action="lambda:InvokeFunction",
            source_arn=http_api_arn
        )

        ami_patch_timeline_lambda.add_permission(
            f"Invoke By Orchestrator Gateway Permission",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            action="lambda:InvokeFunction",
            source_arn=http_api_arn
        )

        ami_patch_mark_for_production_lambda.add_permission(
            f"Invoke By Orchestrator Gateway Permission",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            action="lambda:InvokeFunction",
            source_arn=http_api_arn
        )

        ##########################################################
        # </END> Create AWS API Gateway permissions
        ##########################################################

        ##########################################################
        # <START> Create cross account roles 
        #         to be assumed by other accounts
        ##########################################################

        # Create a role for cross account access to dynamodb    
        dynamodb_crossaccount_role = iam.Role(
            scope=self,
            id="amiOrchestratorDynamodbCARole",
            assumed_by=iam.CompositePrincipal(
                iam.ArnPrincipal(core.Aws.ACCOUNT_ID)
            )
        )

        dynamodb_crossaccount_role_ref = dynamodb_crossaccount_role.node.default_child
        dynamodb_crossaccount_role_ref.add_override(
            "Properties.AssumeRolePolicyDocument.Statement.0.Condition.StringLike.aws:PrincipalArn",
            [
                f"arn:aws:iam::${core.Aws.ACCOUNT_ID}:root"
            ]
        )
        
        # add dynamodb read permissions
        dynamodb_crossaccount_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=[
                    self.ami_lookup_table.table_arn,
                    f"{self.ami_lookup_table.table_arn}/index/*"
                ],
                actions=[
                    "dynamodb:Query",
                    "dynamodb:GetItem"
                ]
            )
        )

        # add kms key permissions
        dynamodb_crossaccount_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=[
                    self.ami_orchestrator_key.key_arn
                ],
                actions=[
                    "kms:Decrypt",
                    "kms:DescribeKey",
                    "kms:Encrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*"
                ]
            )
        )

        dynamodb_crossaccount_role.apply_removal_policy(core.RemovalPolicy.DESTROY)

        # Create a role for cross account access to cloudformation stack exports
        cfn_crossaccount_role = iam.Role(
            scope=self,
            id="amiOrchestratorCfnCARole",
            assumed_by=iam.CompositePrincipal(
                iam.ArnPrincipal(core.Aws.ACCOUNT_ID)
            )
        )

        cfn_crossaccount_role_ref = cfn_crossaccount_role.node.default_child
        cfn_crossaccount_role_ref.add_override(
            "Properties.AssumeRolePolicyDocument.Statement.0.Condition.StringLike.aws:PrincipalArn",
            [
                f"arn:aws:iam::${core.Aws.ACCOUNT_ID}:root"
            ]
        )
        
        # add cloudformation describe stacks permissions
        cfn_crossaccount_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=["*"],
                actions=["cloudformation:DescribeStacks"]
            )
        )

        cfn_crossaccount_role.apply_removal_policy(core.RemovalPolicy.DESTROY)

        ##########################################################
        # </END> Create cross account roles 
        #         to be assumed by other accounts
        ##########################################################


        ##########################################################
        # <START> Stack outputs
        ##########################################################

        core.CfnOutput(
            self, 
            id="ami-orchestrator-cfn-ca-readonly", 
            value=cfn_crossaccount_role.role_arn
        ).override_logical_id(CdkConstants.AMIORCHESTRATOR_CFN_CA_READONLY)

        core.CfnOutput(
            self, 
            id="ami-selection-ca-readonly", 
            value=dynamodb_crossaccount_role.role_arn
        ).override_logical_id(CdkConstants.AMISELECTION_CA_READONLY)

        core.CfnOutput(
            self, 
            id="ami-orchestrator-lookup-db-tablename", 
            value=self.ami_lookup_table.table_name
        ).override_logical_id(CdkConstants.AMISELECTION_TABLENAME)

        core.CfnOutput(
            self, 
            id=f"ami-lifecycle-orchestrator-api", 
            value=apigateway_id
        ).override_logical_id(CdkConstants.AMIORCHESTRATOR_API_GATEWAY_ID)

        core.CfnOutput(
            self, 
            id="ami-lifecycle-orchestrator-api-endpoint", 
            value=apigateway_endpoint
        ).override_logical_id(CdkConstants.AMIORCHESTRATOR_API_GATEWAY_ENDPOINT)
        
        core.CfnOutput(
            self, 
            id="ami-lifecycle-orchestrator-api-stagename", 
            value=apigateway_stagename,
        ).override_logical_id(CdkConstants.AMIORCHESTRATOR_API_GATEWAY_STAGENAME)

        core.CfnOutput(
            self, 
            id="ami-lifecycle-orchestrator-api-url", 
            value=f"{apigateway_endpoint}/{apigateway_stagename}"
        ).override_logical_id(CdkConstants.AMIORCHESTRATOR_API_GATEWAY_URL)

        core.CfnOutput(
            self, 
            id="ami-lifecycle-orchestrator-api-arn", 
            value=http_api_arn
        ).override_logical_id(CdkConstants.AMIORCHESTRATOR_API_GATEWAY_ARN)
    
        core.CfnOutput(
            self, 
            id="ami-lifecycle-patch-component-bucket", 
            value=self.ami_patch_component_bucket.bucket_name
        ).override_logical_id(CdkConstants.AMILIFECYCLE_PATCH_COMPONENT_BUCKET)

        core.CfnOutput(
            self, 
            id="ami-lifecycle-orchestrator-snstopic-arn", 
            value=self.notification_topic.topic_arn
        ).override_logical_id(CdkConstants.AMIORCHESTRATOR_NOTIFICATION_TOPIC_ARN)

        ##########################################################
        # </END> Stack exports
        ##########################################################

        ##########################################################
        ##########################################################
        ##########################################################
        # </END> AMI Orchestrator
        ##########################################################
        ##########################################################
        ##########################################################
    

        ##########################################################
        ##########################################################
        ##########################################################
        # <START> AMI Lifecycle
        ##########################################################
        ##########################################################
        ##########################################################

        VM_IMPORT_ROLE_NAME = "vmimport"

        ##########################################################
        # <START> AMI LIFECYCLE SHARED RESOURCES
        ##########################################################

        # Ec2 security group
        tests_security_group = ec2.SecurityGroup(
            self, 
            'AmiLcEc2TestsSG',
            vpc=self.vpc,
            allow_all_outbound=True,
            description=f"Security group for the AMI Lifecycle test executions"
        )

        tests_role = iam.Role(
            self, 
            f'AmiLcEc2TestRole',
             managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(managed_policy_name='AmazonSSMManagedInstanceCore'),
                iam.ManagedPolicy.from_aws_managed_policy_name(managed_policy_name='AmazonSSMPatchAssociation')
            ],
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com")
        )
        self.ami_orchestrator_key.grant_encrypt_decrypt(tests_role)
        self.ami_orchestrator_key.grant(tests_role, "kms:Describe*")

        tests_role.add_to_policy(iam.PolicyStatement(
            actions=[
                "logs:CreateLogStream",
                "logs:CreateLogGroup",
                "logs:PutLogEvents"
            ],
            resources=[
                f"arn:aws:logs:{self.region}:{self.account}:log-group:/amilifecycle/smoketests*"
            ]
        ))

        tests_role.add_to_policy(iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=["*"],
                actions=[
                    "states:SendTaskSuccess",
                    "states:SendTaskFailure",
                    "states:SendTaskHeartbeat"
                ]
            )
        )

        tests_role.add_to_policy(self.get_sns_publish_policy())
        tests_role.add_to_policy(self.get_sqs_send_message_policy())

        # create an instance profile to attach the role
        tests_instance_profile = iam.CfnInstanceProfile(
            self, 
            f'AmiLcEc2TestInstanceProfile',
            roles=[tests_role.role_name]
        )

        # garbage collector lambda that cleans up timedout ec2 instances
        garbage_collector_lambda_role = iam.Role(
            scope=self,
            id=f"AmiLcGarbageCollectorLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ]
        )

        garbage_collector_lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=["*"],
                actions=[
                    "ec2:*"
                ]
            )
        )

        garbage_collector_lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=[f"arn:aws:ec2:{self.region}:{self.account}:instance/*"],
                actions=[
                    "ec2:TerminateInstances"
                ]
            )
        )

        garbage_collector_lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcGarbageCollectorLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.garbage_collector.ec2_garbage_collector.lambda_handler",
            role=garbage_collector_lambda_role,
            environment={
                "MAX_INSTANCE_RUNTIME_HOURS" : self.config['amiLifecycle']['lifecycleInstanceMaxRuntimeHours']
            },
            timeout=core.Duration.minutes(5),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        garbage_collector_event_rule = events.Rule(
            self,
            f"AmiLcEc2GarbageCollectorEventRule",
            schedule=events.Schedule.rate(core.Duration.minutes(self.config['amiLifecycle']['ec2GarbageCollectorRateMins']))
        )

        garbage_collector_event_rule.add_target(
            events_targets.LambdaFunction(
                    garbage_collector_lambda
                )
            )

        ##########################################################
        # </END> AMI LIFECYCLE SHARED RESOURCES
        ##########################################################

        ##########################################################
        # <START> Define API lambda layers
        ##########################################################

        # https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html#configuration-layers-path
        __lifecycle_deps_layer_dir = f"{os.path.dirname(__file__)}/resources/lambda/layers/ami_lifecycle_deps"
        __lifecycle_deps_layer_output_dir = f"{os.path.dirname(__file__)}/resources/lambda/layers/ami_lifecycle_deps/.lambda_dependencies"

        subprocess.check_call(
            f"rm -fr {__lifecycle_deps_layer_output_dir}".split()
        )
        subprocess.check_call(
            f"pip install --upgrade pip".split()
        )
        subprocess.check_call(
            f"pip install -r {__lifecycle_deps_layer_dir}/requirements.txt -t {__lifecycle_deps_layer_output_dir}/python".split()
        )
        self.ami_lifecycle_deps_layer = aws_lambda.LayerVersion(
            self,
            f"amiLifecycleDependenciesLayer",
            code=aws_lambda.Code.from_asset(__lifecycle_deps_layer_output_dir),
            description="AMI Lifecycle 3rd party dependencies",
            compatible_runtimes=[
                aws_lambda.Runtime.PYTHON_3_9
            ]
        )

        ##########################################################
        # </END> Define API lambda layers
        ##########################################################


        ##########################################################
        # <START> AMI BUILD LIFECYCLE
        ##########################################################

        # create log group for State Machine with 14 day retention period
        build_ami_state_machine_log_group = logs.LogGroup(
            self, 'AmiLcBuildStateMachineLogGroup',
            log_group_name='/aws/vendedlogs/states/amilifecycle/build',
            removal_policy=core.RemovalPolicy.DESTROY,
            retention=logs.RetentionDays.TWO_WEEKS
        )

        # define the state machine lambda
        ami_build_entry_point_lambda = self.get_ami_build_entry_point_lambda()
        ami_build_poll_ami_status_lambda = self.get_ami_build_poll_ami_status_lambda()
        ami_build_ami_details_lambda = self.get_ami_build_ami_details_lambda()
        ami_build_notify_lambda = self.get_ami_build_notify_lambda()

        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_build_entry_point_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_build_poll_ami_status_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_build_ami_details_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_build_notify_lambda)

        ami_build_step_01 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Start EC2 Image Builder pipeline execution",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=ami_build_entry_point_lambda
        )

        ami_build_step_01_result_choice = stepfunctions.Choice(
            self,
            "Was EC2 Image Builder pipeline execution successfull?",
            input_path="$",
            output_path="$"
        )

        ami_build_step_02 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Poll AMI Status until status is AVAILABLE",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=ami_build_poll_ami_status_lambda
        )

        ami_build_step_02_result_choice = stepfunctions.Choice(
            self,
            "Did AMI status request complete successfully?",
            input_path="$",
            output_path="$"
        )

        ami_build_step_02_poll_choice = stepfunctions.Choice(
            self,
            "Is AMI status AVAILABLE?",
            input_path="$",
            output_path="$"
        )

        ami_build_step_02_wait = stepfunctions.Wait(
            self,
            "Wait to recheck AMI status is AVAILABLE",
            time=stepfunctions.WaitTime.duration(core.Duration.minutes(3))
        )

        ami_build_step_03 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Get AMI Details",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=ami_build_ami_details_lambda
        )

        ami_build_step_03_result_choice = stepfunctions.Choice(
            self,
            "Were AMI details obtained successfully?",
            input_path="$",
            output_path="$"
        )

        ami_build_step_04 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Notify API Orchestrator of AMI Build completion",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=ami_build_notify_lambda
        )

        ami_build_step_04_send_notification = stepfunctions_tasks.SqsSendMessage(
            self,
            id=f"Notify AMI Build to CreationReceiverQueue"[:79],
            queue=self.ami_creation_receiver_queue,
            message_body=stepfunctions.TaskInput.from_object(
                {
                    "id": ''.join(random.choices(string.ascii_letters + string.digits, k = 12)),
                    "task_token": stepfunctions.JsonPath.task_token,
                    "task_details": stepfunctions.TaskInput.from_json_path_at("$.event_outputs")
                }
            ),
            integration_pattern=stepfunctions.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
            timeout=core.Duration.minutes(self.config['amiLifecycle']['amiCreationReceiverTimeout'])
        )

        ami_build_step_04_result_choice = stepfunctions.Choice(
            self,
            "Was API Orchestrator AMI Build notification successfull?",
            input_path="$",
            output_path="$"
        )

        ami_build_step_success = stepfunctions.Succeed(
            self,
            "AMI Build event success."
        )

        ami_build_step_fail = stepfunctions.Fail(
            self,
            "AMI Build event failure."
        )

        ami_build_step_01_result_choice.when(stepfunctions.Condition.string_equals('$.build_ami_operation.output.status', "ERROR"),
                                    ami_build_step_fail).otherwise(ami_build_step_02)

        ami_build_step_02.next(ami_build_step_02_result_choice)

        ami_build_step_02_result_choice.when(stepfunctions.Condition.string_equals('$.build_ami_operation.output.status', "ERROR"),
                            ami_build_step_fail).otherwise(ami_build_step_02_poll_choice)

        ami_build_step_02_poll_choice.when(stepfunctions.Condition.string_equals('$.build_ami_operation.output.ami_state', "AVAILABLE"),
                            ami_build_step_03).otherwise(ami_build_step_02_wait)

        ami_build_step_02_wait.next(ami_build_step_02)

        ami_build_step_03.next(ami_build_step_03_result_choice)

        ami_build_step_03_result_choice.when(stepfunctions.Condition.string_equals('$.build_ami_operation.output.status', "ERROR"),
                                    ami_build_step_fail).otherwise(ami_build_step_04)

        ami_build_step_04.next(ami_build_step_04_send_notification)

        ami_build_step_04_send_notification.next(ami_build_step_04_result_choice)

        ami_build_step_04_result_choice.when(stepfunctions.Condition.string_equals('$.receiver_status', "ERROR"),
                                    ami_build_step_fail).otherwise(ami_build_step_success)


        # step functions state machine
        ami_build_state_machine = stepfunctions.StateMachine(
            self, 
            f"LifeCycleAmiBuildStateMachineName",
            timeout=core.Duration.minutes(self.config['amiLifecycle']['stateMachines']['amiBuildEventStateMachineTimeoutMins']),
            definition=ami_build_step_01.next(ami_build_step_01_result_choice),
            logs=stepfunctions.LogOptions(
                destination=build_ami_state_machine_log_group,
                level=stepfunctions.LogLevel.ALL
            )
        )

        # export the arn of the ami build state machine which will be consumed by other processes
        core.CfnOutput(
            self,
            f"LifeCycleAmiBuildStateMachineNameOutput",
            value=ami_build_state_machine.state_machine_arn,
            description="AMI Lifecycle AMI Build Event State Machine"
        ).override_logical_id(CdkConstants.AMILIFECYCLE_AMI_BUILD_STATEMACHINE_NAME)


        ##########################################################
        # </END> AMI BUILD LIFECYCLE
        ##########################################################


        ##########################################################
        # <START> SMOKE TESTS LIFECYCLE
        ##########################################################

        # create log group for State Machine with 14 day retention period
        smoke_tests_state_machine_log_group = logs.LogGroup(
            self, 'AmiLcSmokeTestsStateMachineLogGroup',
            log_group_name='/aws/vendedlogs/states/amilifecycle/smoketests',
            removal_policy=core.RemovalPolicy.DESTROY,
            retention=logs.RetentionDays.TWO_WEEKS
        )

        # create log group for EC2 Smoke Tests with 14 day retention period
        smoke_tests_results_log_group = logs.LogGroup(
            self, 'AmiLcSmokeTestsResultsLogGroup',
            log_group_name='/amilifecycle/smoketests',
            removal_policy=core.RemovalPolicy.DESTROY,
            retention=logs.RetentionDays.TWO_WEEKS
        )

        # queue used to trigger smoke test execution
        ami_smoke_tests_executor_queue = sqs.Queue(
            self, 
            f"AmiLcSmokeTestsExecutorQueue",
            encryption=sqs.QueueEncryption.KMS_MANAGED,
            visibility_timeout=core.Duration.minutes(self.config['amiLifecycle']['stateMachines']['smokeTestEventStateMachineSqsTimeoutMins'])
        )

        ami_smoke_tests_executor_queue.grant_send_messages(IAMPrincipals.STEP_FUNCTIONS.value)

        # upload test resources to s3 bucket
        smoke_tests_assets = assets.Asset(
            self, 
            f"AmiLcSmokeTestsAssets",
            path=f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle/app/smoke_tests/smoketestsscripts",
        )
        smoke_tests_assets.grant_read(tests_role)

        # state machine lambda functions
        smoke_test_entry_point_lambda = self.get_smoke_tests_entry_point_lambda()
        smoke_test_tests_executor_lambda = self.get_smoke_tests_executor_lambda(
            s3_object_url=smoke_tests_assets.s3_object_url,
            sqs_queue_url=ami_smoke_tests_executor_queue.queue_url,
            log_group_name=smoke_tests_results_log_group.log_group_name,
            vpc=self.vpc,
            security_group=tests_security_group,
            ec2_instance_profile=tests_instance_profile,
            tests_role=tests_role
        )
        smoke_test_tear_down_lambda = self.get_smoke_tests_tear_down_lambda()
        smoke_test_notify_lambda = self.get_smoke_tests_notify_lambda()

        self.ami_orchestrator_key.grant_encrypt_decrypt(smoke_test_entry_point_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(smoke_test_tests_executor_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(smoke_test_tear_down_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(smoke_test_notify_lambda)

        # grant notify lanbda access to ami creation and ami patch queue
        self.ami_creation_receiver_queue.grant_send_messages(smoke_test_notify_lambda)
        self.ami_patch_receiver_queue.grant_send_messages(smoke_test_notify_lambda)

        # give the executor lambda access to the SQS queues
        ami_smoke_tests_executor_queue.grant_consume_messages(smoke_test_tests_executor_lambda)
        smoke_test_tests_executor_lambda.add_event_source(
            event_sources.SqsEventSource(ami_smoke_tests_executor_queue)
        )

        smoke_test_step_01 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Prepare AMI Smoke Tests execution",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=smoke_test_entry_point_lambda
        )

        smoke_test_step_01_result_choice = stepfunctions.Choice(
            self,
            "Was AMI Smoke Tests preparation successfull?",
            input_path="$",
            output_path="$"
        )

        smoke_test_step_02_send_notification = stepfunctions_tasks.SqsSendMessage(
            self,
            id=f"Execute AMI Smoke Tests",
            queue=ami_smoke_tests_executor_queue,
            message_body=stepfunctions.TaskInput.from_object(
                {
                    "id": ''.join(random.choices(string.ascii_letters + string.digits, k = 12)),
                    "task_token": stepfunctions.JsonPath.task_token,
                    "task_details": stepfunctions.TaskInput.from_json_path_at("$.event_outputs")
                }
            ),
            integration_pattern=stepfunctions.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
            timeout=core.Duration.minutes(self.config['amiLifecycle']['stateMachines']['smokeTestEventStateMachineSqsTimeoutMins']),
        )

        smoke_test_step_02_result_choice = stepfunctions.Choice(
            self,
            "Did AMI Smoke Tests complete successfully?",
            input_path="$",
            output_path="$"
        )

        smoke_test_step_02_wait = stepfunctions.Wait(
            self,
            "Wait for EC2 smoke tests logs to be pushed to CloudWatch",
            time=stepfunctions.WaitTime.duration(
                core.Duration.minutes(self.config['amiLifecycle']['ec2TestInstanceLogsShipDelay'])
            )
        )

        smoke_test_step_03 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Terminate EC2 instance used for Smoke Tests execution",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=smoke_test_tear_down_lambda
        )

        smoke_test_step_03_result_choice = stepfunctions.Choice(
            self,
            "Was Smoke Tests EC2 instance terminated successfull?",
            input_path="$",
            output_path="$"
        )

        smoke_test_step_04 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Notify API Orchestrator of Smoke Tests completion",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=smoke_test_notify_lambda
        )

        smoke_test_step_04_result_choice = stepfunctions.Choice(
            self,
            "Was API Orchestrator Smoke Tests notification successfull?",
            input_path="$",
            output_path="$"
        )

        smoke_test_step_success = stepfunctions.Succeed(
            self,
            "AMI Smoke Tests event success."
        )

        smoke_test_step_fail = stepfunctions.Fail(
            self,
            "AMI Smoke Tests event failure."
        )

        smoke_test_step_01_result_choice.when(stepfunctions.Condition.string_equals('$.smoke_test_operation.output.status', "ERROR"),
                                    smoke_test_step_fail).otherwise(smoke_test_step_02_send_notification)

        smoke_test_step_02_send_notification.next(smoke_test_step_02_result_choice)

        smoke_test_step_02_result_choice.when(stepfunctions.Condition.string_equals('$.receiver_status', "ERROR"),
                                    smoke_test_step_fail).otherwise(smoke_test_step_02_wait)

        smoke_test_step_02_wait.next(smoke_test_step_03)

        smoke_test_step_03.next(smoke_test_step_03_result_choice)

        smoke_test_step_03_result_choice.when(stepfunctions.Condition.string_equals('$.smoke_test_operation.output.status', "ERROR"),
                                    smoke_test_step_fail).otherwise(smoke_test_step_04)

        smoke_test_step_04.next(smoke_test_step_04_result_choice)

        smoke_test_step_04_result_choice.when(stepfunctions.Condition.string_equals('$.smoke_test_operation.output.status', "ERROR"),
                                    smoke_test_step_fail).otherwise(smoke_test_step_success)

        # step functions state machine
        smoke_test_state_machine = stepfunctions.StateMachine(
            self, 
            f"LifeCycleSmokeTestsStateMachineName",
            timeout=core.Duration.minutes(self.config['amiLifecycle']['stateMachines']['smokeTestEventStateMachineTimeoutMins']),
            definition=smoke_test_step_01.next(smoke_test_step_01_result_choice),
            logs=stepfunctions.LogOptions(
                destination=smoke_tests_state_machine_log_group,
                level=stepfunctions.LogLevel.ALL
            )
        )

        # export the arn of the smoke test state machine which will be consumed by other processes
        core.CfnOutput(
            self,
            f"LifeCycleSmokeTestsStateMachineNameOutput",
            value=smoke_test_state_machine.state_machine_arn,
            description="AMI Lifecycle Smoke Tests Event State Machine"
        ).override_logical_id(CdkConstants.AMILIFECYCLE_SMOKE_TESTS_STATEMACHINE_NAME)

        ##########################################################
        # </END> SMOKE TESTS LIFECYCLE
        ##########################################################


        ##########################################################
        # <START> VULNERABILITY SCANS LIFECYCLE
        ##########################################################

        # create log group for State Machine with 14 day retention period
        vulnerability_scans_state_machine_log_group = logs.LogGroup(
            self, 'AmiLcVulnerabilityScansStateMachineLogGroup',
            log_group_name='/aws/vendedlogs/states/amilifecycle/vulnerabilityscans',
            removal_policy=core.RemovalPolicy.DESTROY,
            retention=logs.RetentionDays.TWO_WEEKS
        )

        # Kms key and s3 bucket for inspector findings
        vulnerability_scans_key = kms.Key(
            self, 
            "VulnerabilityScansFindingsKey",
            admins=[iam.AccountPrincipal(account_id=core.Aws.ACCOUNT_ID)],
            enable_key_rotation=True,
            enabled=True,
            description="KMS key used with Vulnerability Scans in Ami Lifecycle project",
            removal_policy=core.RemovalPolicy.DESTROY,
            alias="vulnerability-scans-alias"
        )

        vulnerability_scans_bucket = s3.Bucket(
            self, 
            "InspectorV2Findings",
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            removal_policy=core.RemovalPolicy.DESTROY,
            public_read_access=False,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True
        )

        vulnerability_scans_key.grant_encrypt_decrypt(iam.ServicePrincipal(service='inspector2.amazonaws.com'))
        vulnerability_scans_bucket.grant_read_write(iam.ServicePrincipal(service='inspector2.amazonaws.com'))

        # state machine lambda functions
        vulnerability_scans_entry_point_lambda = self.get_vulnerability_scans_entry_point_lambda()
        vulnerability_scans_launch_instance_lambda = self.get_vulnerability_scans_launch_instance_lambda(
            vpc=self.vpc,
            security_group=tests_security_group,
            ec2_instance_profile=tests_instance_profile,
            tests_role=tests_role
        )
        vulnerability_scans_poll_status_lambda = self.get_vulnerability_scans_poll_status_lambda()
        vulnerability_scans_findings_lambda = self.get_vulnerability_scans_findings_lambda(
            findings_bucket_name=vulnerability_scans_bucket.bucket_name,
            vulnerability_scans_key_arn=vulnerability_scans_key.key_arn
        )
        vulnerability_scans_tear_down_lambda = self.get_vulnerability_scans_tear_down_lambda()
        vulnerability_scans_publish_metrics_lambda = self.get_vulnerability_scans_publish_metrics_lambda()
        vulnerability_scans_notify_lambda = self.get_vulnerability_scans_notify_lambda()

        self.ami_orchestrator_key.grant_encrypt_decrypt(vulnerability_scans_entry_point_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(vulnerability_scans_launch_instance_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(vulnerability_scans_poll_status_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(vulnerability_scans_findings_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(vulnerability_scans_tear_down_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(vulnerability_scans_publish_metrics_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(vulnerability_scans_notify_lambda)

        # grant notify lanbda access to ami creation and ami patch queue
        self.ami_creation_receiver_queue.grant_send_messages(vulnerability_scans_notify_lambda)
        self.ami_patch_receiver_queue.grant_send_messages(vulnerability_scans_notify_lambda)

        vulnerability_scans_step_01 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Prepare AMI Vulnerability Scans execution",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=vulnerability_scans_entry_point_lambda
        )

        vulnerability_scans_step_01_result_choice = stepfunctions.Choice(
            self,
            "Was AMI Vulnerability Scans preparation successfull?",
            input_path="$",
            output_path="$"
        )

        vulnerability_scans_step_02 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Launch EC2 Instance for AWS Inspector V2 AMI Vulnerability Scaning",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=vulnerability_scans_launch_instance_lambda
        )

        vulnerability_scans_step_02_result_choice = stepfunctions.Choice(
            self,
            "Was EC2 Instance launched successfull?",
            input_path="$",
            output_path="$"
        )

        vulnerability_scans_step_02_wait = stepfunctions.Wait(
            self,
            "Wait for EC2 instance to register with SSM and execute scan",
            time=stepfunctions.WaitTime.duration(core.Duration.minutes(3))
        )

        vulnerability_scans_step_03 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Poll AWS Inspector V2 until status is SUCCESSFUL",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=vulnerability_scans_poll_status_lambda
        )

        vulnerability_scans_step_03_poll_choice = stepfunctions.Choice(
            self,
            "Is AWS Inspector V2 status SUCCESSFUL?",
            input_path="$",
            output_path="$"
        )

        vulnerability_scans_step_03_result_choice = stepfunctions.Choice(
            self,
            "Check AWS Inspector V2 status SUCCESSFUL",
            input_path="$",
            output_path="$"
        )

        vulnerability_scans_step_03_wait = stepfunctions.Wait(
            self,
            "Wait to recheck AWS Inspector V2 status is SUCCESSFUL",
            time=stepfunctions.WaitTime.duration(core.Duration.minutes(1))
        )

        vulnerability_scans_step_04 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Get AWS Inspector V2 AMI Vulnerability Scan findings",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=vulnerability_scans_findings_lambda
        )

        vulnerability_scans_step_04_result_choice = stepfunctions.Choice(
            self,
            "Were AWS Inspector V2 AMI Vulnerability Scan findings obtained successfull?",
            input_path="$",
            output_path="$"
        )

        vulnerability_scans_step_05 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Put AWS Inspector V2 AMI Vulnerability Scanning metric data in CloudWatch",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=vulnerability_scans_publish_metrics_lambda
        )

        vulnerability_scans_step_05_result_choice = stepfunctions.Choice(
            self,
            "Was AWS Inspector V2 metric data put successfully?",
            input_path="$",
            output_path="$"
        )

        vulnerability_scans_step_06 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Terminate EC2 Instance used for Vulnerability Scanning",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=vulnerability_scans_tear_down_lambda
        )

        vulnerability_scans_step_06_result_choice = stepfunctions.Choice(
            self,
            "Was AWS Inspector V2 EC2 Instance terminated successfully?",
            input_path="$",
            output_path="$"
        )

        vulnerability_scans_step_07 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Notify Vulnerability Scan results to ReceiverQueue",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=vulnerability_scans_notify_lambda
        )

        vulnerability_scans_step_07_result_choice = stepfunctions.Choice(
            self,
            "Was Vulnerability Scan result notification successfull?",
            input_path="$",
            output_path="$"
        )

        vulnerability_scans_step_success = stepfunctions.Succeed(
            self,
            "Vulnerability Scans event success."
        )

        vulnerability_scans_step_fail = stepfunctions.Fail(
            self,
            "Vulnerability Scans event failure."
        )

        vulnerability_scans_step_01_result_choice.when(stepfunctions.Condition.string_equals('$.vulnerability_scans_operation.output.status', "ERROR"),
                                    vulnerability_scans_step_fail).otherwise(vulnerability_scans_step_02)

        vulnerability_scans_step_02.next(vulnerability_scans_step_02_result_choice)

        vulnerability_scans_step_02_result_choice.when(stepfunctions.Condition.string_equals('$.vulnerability_scans_operation.output.status', "ERROR"),
                            vulnerability_scans_step_fail).otherwise(vulnerability_scans_step_02_wait)

        vulnerability_scans_step_02_wait.next(vulnerability_scans_step_03)

        vulnerability_scans_step_03.next(vulnerability_scans_step_03_result_choice)

        vulnerability_scans_step_03_result_choice.when(stepfunctions.Condition.string_equals('$.vulnerability_scans_operation.output.status', "ERROR"),
                            vulnerability_scans_step_fail).otherwise(vulnerability_scans_step_03_poll_choice)

        vulnerability_scans_step_03_poll_choice.when(
            stepfunctions.Condition.and_(
                stepfunctions.Condition.string_equals('$.vulnerability_scans_operation.output.scan_status_code', "ACTIVE"),
                stepfunctions.Condition.string_equals('$.vulnerability_scans_operation.output.scan_status_reason', "SUCCESSFUL"),
            ),
            vulnerability_scans_step_04
        ).otherwise(vulnerability_scans_step_03_wait)

        vulnerability_scans_step_03_wait.next(vulnerability_scans_step_03)

        vulnerability_scans_step_04.next(vulnerability_scans_step_04_result_choice)

        vulnerability_scans_step_04_result_choice.when(stepfunctions.Condition.string_equals('$.vulnerability_scans_operation.output.status', "ERROR"),
                                    vulnerability_scans_step_fail).otherwise(vulnerability_scans_step_05)

        vulnerability_scans_step_05.next(vulnerability_scans_step_05_result_choice)

        vulnerability_scans_step_05_result_choice.when(stepfunctions.Condition.string_equals('$.vulnerability_scans_operation.output.status', "ERROR"),
                                    vulnerability_scans_step_fail).otherwise(vulnerability_scans_step_06)

        vulnerability_scans_step_06.next(vulnerability_scans_step_06_result_choice)

        vulnerability_scans_step_06_result_choice.when(stepfunctions.Condition.string_equals('$.vulnerability_scans_operation.output.status', "ERROR"),
                            vulnerability_scans_step_fail).otherwise(vulnerability_scans_step_07)

        vulnerability_scans_step_07.next(vulnerability_scans_step_07_result_choice)

        vulnerability_scans_step_07_result_choice.when(stepfunctions.Condition.string_equals('$.vulnerability_scans_operation.output.status', "ERROR"),
                                    vulnerability_scans_step_fail).otherwise(vulnerability_scans_step_success)


        # step functions state machine
        vulnerability_scans_state_machine = stepfunctions.StateMachine(
            self, 
            f"LifeCycleVulnerabilityScansStateMachineName",
            timeout=core.Duration.minutes(self.config['amiLifecycle']['stateMachines']['vulnerabilityScansEventStateMachineTimeoutMins']),
            definition=vulnerability_scans_step_01.next(vulnerability_scans_step_01_result_choice),
            logs=stepfunctions.LogOptions(
                destination=vulnerability_scans_state_machine_log_group,
                level=stepfunctions.LogLevel.ALL
            )
        )

        # export the arn of the vulnerability scans state machine which will be consumed by other processes
        core.CfnOutput(
            self,
            f"LifeCycleVulnerabilityScansStateMachineNameOutput",
            value=vulnerability_scans_state_machine.state_machine_arn,
            description="AMI Lifecycle Vulnerability Scans Event State Machine"
        ).override_logical_id(CdkConstants.AMILIFECYCLE_VULNERABILITY_SCANS_STATEMACHINE_NAME)
   
 
        ##########################################################
        # </END> VULNERABILITY SCANS LIFECYCLE
        ##########################################################


        ##########################################################
        # <START> QA CERTIFICATION LIFECYCLE
        ##########################################################

        self.qa_sns_topic = sns.Topic(
            self, "QANotificationTopic",
            master_key=self.ami_orchestrator_key
        )

        sns.Subscription(
            self, "Subscription",
            topic=self.qa_sns_topic,
            endpoint=self.config['amiLifecycle']["qaNotificationEmailAddress"],
            protocol=sns.SubscriptionProtocol.EMAIL
        )

        self.ami_orchestrator_key.grant_encrypt_decrypt(IAMPrincipals.SNS.value)

        # Role to be assumed for the VMDK export
        # This role requires a specific name; vmimport
        # For this reason the role is created as a PerRegion resource
        # in l3_constructs.ami.amiLifecycle.VmdkExport class
        vmimport_role_arn = f"arn:aws:iam::{self.account}:role/{VM_IMPORT_ROLE_NAME}"

        self.vm_import_role = iam.Role.from_role_arn(
            self,
            id=f"vmdkImportRole",
            role_arn=vmimport_role_arn
        )

        # add the necessary policies to kms keys
        self.ami_orchestrator_key.grant_encrypt_decrypt(IAMPrincipals.VM_IMPORT.value)
        self.ami_orchestrator_key.grant_encrypt_decrypt(IAMPrincipals.EC2.value)

        # create log group for State Machine with 14 day retention period
        qa_certification_state_machine_log_group = logs.LogGroup(
            self, 'AmiLcQACertifyStateMachineLogGroup',
            log_group_name='/aws/vendedlogs/states/amilifecycle/qacertification',
            removal_policy=core.RemovalPolicy.DESTROY
        )

        # define the state machine lambda
        qa_certification_entry_point_lambda = self.get_qa_certification_entry_point_lambda()
        qa_certification_poll_ami_status_lambda = self.get_qa_certification_poll_ami_status_lambda()
        qa_certification_vmdk_export_lambda = self.get_qa_certification_vmdk_export_lambda(
            vmdk_export_bucket_arn=self.vmdk_export_bucket_arn
        )
        qa_certification_poll_vmdk_status_lambda = self.get_qa_certification_poll_vmdk_status_lambda()
        qa_certification_generate_url_lambda = self.get_qa_certification_generate_url_lambda(
            vmdk_export_bucket_arn=self.vmdk_export_bucket_arn
        )
        qa_certification_notify_external_qa_lambda = self.get_qa_certification_notify_external_qa_lambda()
        qa_certification_notify_lambda = self.get_qa_certification_notify_lambda()

        self.ami_orchestrator_key.grant_encrypt_decrypt(qa_certification_entry_point_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(qa_certification_poll_ami_status_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(qa_certification_vmdk_export_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(qa_certification_poll_vmdk_status_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(qa_certification_generate_url_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(qa_certification_notify_external_qa_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(qa_certification_notify_lambda)

        # grant publish on qa sns topic
        self.qa_sns_topic.grant_publish(qa_certification_notify_external_qa_lambda)

        qa_certification_step_01 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Start QA Certification request process",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=qa_certification_entry_point_lambda
        )

        qa_certification_step_01_result_choice = stepfunctions.Choice(
            self,
            "Can proceed with QA Certification request process?",
            input_path="$",
            output_path="$"
        )

        qa_certification_step_02 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Poll QA AMI Status until status is AVAILABLE",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=qa_certification_poll_ami_status_lambda
        )

        qa_certification_step_02_poll_choice = stepfunctions.Choice(
            self,
            "Is QA AMI status AVAILABLE?",
            input_path="$",
            output_path="$"
        )

        qa_certification_step_02_result_choice = stepfunctions.Choice(
            self,
            "Check AMI status AVAILABLE?",
            input_path="$",
            output_path="$"
        )

        qa_certification_step_02_wait = stepfunctions.Wait(
            self,
            "Wait to recheck QA AMI status is AVAILABLE",
            time=stepfunctions.WaitTime.duration(core.Duration.minutes(3))
        )

        qa_certification_step_03 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Export QA AMI to VMDK",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=qa_certification_vmdk_export_lambda
        )

        qa_certification_step_03_result_choice = stepfunctions.Choice(
            self,
            "Was VMDK export process started successfully?",
            input_path="$",
            output_path="$"
        )


        qa_certification_step_04 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Poll VMDK export status until AVAILABLE",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=qa_certification_poll_vmdk_status_lambda
        )

        qa_certification_step_04_poll_choice = stepfunctions.Choice(
            self,
            "Is VMDK export status AVAILABLE?",
            input_path="$",
            output_path="$"
        )

        qa_certification_step_04_result_choice = stepfunctions.Choice(
            self,
            "Check VMDK export status is AVAILABLE?",
            input_path="$",
            output_path="$"
        )

        qa_certification_step_04_wait = stepfunctions.Wait(
            self,
            "Wait to recheck VMDK export status is AVAILABLE",
            time=stepfunctions.WaitTime.duration(core.Duration.minutes(3))
        )

        qa_certification_step_05 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Generate VMDK S3 download URL",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=qa_certification_generate_url_lambda
        )

        qa_certification_step_05_result_choice = stepfunctions.Choice(
            self,
            "Was VMDK S3 download URL generated successfully?",
            input_path="$",
            output_path="$"
        )

        qa_certification_step_06 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Send notification to external QA team",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=qa_certification_notify_external_qa_lambda
        )

        qa_certification_step_06_result_choice = stepfunctions.Choice(
            self,
            "Was notification sent to external QA team successfully?",
            input_path="$",
            output_path="$"
        )

        qa_certification_step_07 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Prepare QA cert notification",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=qa_certification_notify_lambda
        )

        qa_certification_step_08_send_notification = stepfunctions_tasks.SqsSendMessage(
            self,
            id=f"Notify QA Cert to CreationReceiverQueue"[:79],
            queue=self.ami_creation_receiver_queue,
            message_body=stepfunctions.TaskInput.from_object(
                {
                    "id": ''.join(random.choices(string.ascii_letters + string.digits, k = 12)),
                    "task_token": stepfunctions.JsonPath.task_token,
                    "task_details": stepfunctions.TaskInput.from_json_path_at("$.event_outputs")
                }
            ),
            integration_pattern=stepfunctions.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
            timeout=core.Duration.minutes(self.config['amiLifecycle']['amiCreationReceiverTimeout'])
        )

        qa_certification_step_08_result_choice = stepfunctions.Choice(
            self,
            "Was API Orchestrator QA Certification notification successfull?",
            input_path="$",
            output_path="$"
        )

        qa_certification_step_success = stepfunctions.Succeed(
            self,
            "QA Certification event success."
        )

        qa_certification_step_fail = stepfunctions.Fail(
            self,
            "QA Certification event failure."
        )

        qa_certification_step_01_result_choice.when(stepfunctions.Condition.string_equals('$.qa_certification_operation.output.status', "ERROR"),
                                    qa_certification_step_fail).otherwise(qa_certification_step_02)

        qa_certification_step_02.next(qa_certification_step_02_result_choice)

        qa_certification_step_02_result_choice.when(stepfunctions.Condition.string_equals('$.qa_certification_operation.output.status', "ERROR"),
                            qa_certification_step_fail).otherwise(qa_certification_step_02_poll_choice)

        qa_certification_step_02_poll_choice.when(
            stepfunctions.Condition.and_(
                stepfunctions.Condition.string_equals('$.qa_certification_operation.output.ami_state', "AVAILABLE"),
                stepfunctions.Condition.boolean_equals('$.qa_certification_operation.output.active_vmdk_export_tasks', False)
        ), qa_certification_step_03).otherwise(qa_certification_step_02_wait)

        qa_certification_step_02_wait.next(qa_certification_step_02)

        qa_certification_step_03.next(qa_certification_step_03_result_choice)

        qa_certification_step_03_result_choice.when(stepfunctions.Condition.string_equals('$.qa_certification_operation.output.status', "ERROR"),
                                    qa_certification_step_fail).otherwise(qa_certification_step_04)

        qa_certification_step_04.next(qa_certification_step_04_result_choice)

        qa_certification_step_04_result_choice.when(stepfunctions.Condition.string_equals('$.qa_certification_operation.output.status', "ERROR"),
                            qa_certification_step_fail).otherwise(qa_certification_step_04_poll_choice)

        qa_certification_step_04_poll_choice.when(stepfunctions.Condition.string_equals('$.qa_certification_operation.output.export_image_task_status', "COMPLETED"),
                            qa_certification_step_05).otherwise(qa_certification_step_04_wait)

        qa_certification_step_04_wait.next(qa_certification_step_04)

        qa_certification_step_05.next(qa_certification_step_05_result_choice)

        qa_certification_step_05_result_choice.when(stepfunctions.Condition.string_equals('$.qa_certification_operation.output.status', "ERROR"),
                                    qa_certification_step_fail).otherwise(qa_certification_step_06)

        qa_certification_step_06.next(qa_certification_step_06_result_choice)

        qa_certification_step_06_result_choice.when(stepfunctions.Condition.string_equals('$.qa_certification_operation.output.status', "ERROR"),
                                    qa_certification_step_fail).otherwise(qa_certification_step_07)

        qa_certification_step_07.next(qa_certification_step_08_send_notification)

        qa_certification_step_08_send_notification.next(qa_certification_step_08_result_choice)

        qa_certification_step_08_result_choice.when(stepfunctions.Condition.string_equals('$.receiver_status', "ERROR"),
                                    qa_certification_step_fail).otherwise(qa_certification_step_success)               
    
        # step functions state machine
        qa_certification_state_machine = stepfunctions.StateMachine(
            self, 
            f"LifeCycleQACertificationStateMachineName",
            timeout=core.Duration.minutes(self.config['amiLifecycle']['stateMachines']['qaCertificationEventStateMachineTimeoutMins']),
            definition=qa_certification_step_01.next(qa_certification_step_01_result_choice),
            logs=stepfunctions.LogOptions(
                destination=qa_certification_state_machine_log_group,
                level=stepfunctions.LogLevel.ALL
            )
        )

        # export the arn of the ami build state machine which will be consumed by other processes
        core.CfnOutput(
            self,
            f"LifeCycleQACertificationStateMachineNameOutput",
            value=qa_certification_state_machine.state_machine_arn,
            description="AMI Lifecycle QA CERTIFICATION Event State Machine"
        ).override_logical_id(CdkConstants.AMILIFECYCLE_QA_CERTIFICATION_STATEMACHINE_NAME)

        
        ##########################################################
        # </END> QA CERTIFICATION LIFECYCLE
        ##########################################################


        ##########################################################
        # <START> AMI PATCH LIFECYCLE
        ##########################################################

        # create log group for State Machine with 14 day retention period
        patch_ami_state_machine_log_group = logs.LogGroup(
            self, 'AmiLcPatchStateMachineLogGroup',
            log_group_name='/aws/vendedlogs/states/amilifecycle/patch',
            removal_policy=core.RemovalPolicy.DESTROY
        )

        # define the state machine lambda
        ami_patch_entry_point_lambda = self.get_ami_patch_entry_point_lambda()
        ami_patch_create_component_lambda = self.get_ami_patch_create_component_lambda(self.ami_orchestrator_key)
        ami_patch_create_image_recipe_lambda = self.get_ami_patch_create_image_recipe_lambda()
        ami_patch_start_image_pipeline_lambda = self.get_ami_patch_start_image_pipeline_lambda()
        ami_patch_create_imagepipeline_lambda = self.get_ami_patch_create_imagepipeline_lambda()
        ami_patch_poll_ami_status_lambda = self.get_ami_patch_poll_ami_status_lambda()
        ami_patch_ami_details_lambda = self.get_ami_patch_ami_details_lambda()
        ami_patch_delete_dynamic_imagebuilder_lambda = self.get_ami_patch_delete_dynamic_imagebuilder_lambda()
        ami_patch_notify_lambda = self.get_ami_patch_notify_lambda()

        # grant lambdas access to the orchestrator key
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_patch_entry_point_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_patch_create_component_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_patch_create_image_recipe_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_patch_create_imagepipeline_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_patch_start_image_pipeline_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_patch_poll_ami_status_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_patch_ami_details_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_patch_delete_dynamic_imagebuilder_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(ami_patch_notify_lambda)

        # grant create imagebuilder pipeline access to the Image Builder kms key
        self.imagebuilder_kms_key = kms.Key.from_key_arn(self, 'image-builder-kms-key-ref', key_arn=self.imagebuilder_kms_key_arn)
        self.imagebuilder_kms_key.grant_encrypt_decrypt(ami_patch_create_imagepipeline_lambda)

        # grant the create component lambda ccess to read the component from S3 bucket
        self.ami_patch_component_bucket.grant_read_write(ami_patch_create_component_lambda)

        ami_patch_step_01 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Gather AMI Patch processing data",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=ami_patch_entry_point_lambda
        )

        ami_patch_step_01_result_choice = stepfunctions.Choice(
            self,
            "Was AMI Patch processing data verification successfull?",
            input_path="$",
            output_path="$"
        )

        ami_patch_step_02 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Create Image Builder patch component",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=ami_patch_create_component_lambda
        )

        ami_patch_step_02_result_choice = stepfunctions.Choice(
            self,
            "Was Image Builder patch component created successfully?",
            input_path="$",
            output_path="$"
        )

        ami_patch_step_03 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Create Image Builder recipe",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=ami_patch_create_image_recipe_lambda
        )

        ami_patch_step_03_result_choice = stepfunctions.Choice(
            self,
            "Was Image Builder recipe created successfully?",
            input_path="$",
            output_path="$"
        )

        ami_patch_step_04 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Create Image Builder pipeline",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=ami_patch_create_imagepipeline_lambda
        )

        ami_patch_step_04_result_choice = stepfunctions.Choice(
            self,
            "Was Image Builder pipeline created successfully?",
            input_path="$",
            output_path="$"
        )

        ami_patch_step_05 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Start Image Builder pipeline",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=ami_patch_start_image_pipeline_lambda
        )

        ami_patch_step_05_result_choice = stepfunctions.Choice(
            self,
            "Was Image Builder pipeline started successfully?",
            input_path="$",
            output_path="$"
        )

        ami_patch_step_06 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Poll AMI Patch Status until status is AVAILABLE",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=ami_patch_poll_ami_status_lambda
        )

        ami_patch_step_06_result_choice = stepfunctions.Choice(
            self,
            "Did AMI Patch Status request complete successfully?",
            input_path="$",
            output_path="$"
        )

        ami_patch_step_06_poll_choice = stepfunctions.Choice(
            self,
            "Is AMI Patch status AVAILABLE?",
            input_path="$",
            output_path="$"
        )

        ami_patch_step_06_wait = stepfunctions.Wait(
            self,
            "Wait to recheck AMI Patch status is AVAILABLE",
            time=stepfunctions.WaitTime.duration(core.Duration.minutes(3))
        )

        ami_patch_step_07 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Get AMI Patch Details",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=ami_patch_ami_details_lambda
        )

        ami_patch_step_07_result_choice = stepfunctions.Choice(
            self,
            "Were AMI Patch details obtained successfully?",
            input_path="$",
            output_path="$"
        )

        ami_patch_step_08 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Delete dynamically created EC2 ImageBuilder resources",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=ami_patch_delete_dynamic_imagebuilder_lambda
        )

        ami_patch_step_08_result_choice = stepfunctions.Choice(
            self,
            "Were dynamic EC2 ImageBuilder resources deleted successfully?",
            input_path="$",
            output_path="$"
        )

        ami_patch_step_09 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Notify API Orchestrator of AMI Patch completion",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=ami_patch_notify_lambda
        )

        ami_patch_step_10_send_notification = stepfunctions_tasks.SqsSendMessage(
            self,
            id=f"Notify AMI Patch to PatchReceiverQueue"[:79],
            queue=self.ami_patch_receiver_queue,
            message_body=stepfunctions.TaskInput.from_object(
                {
                    "id": ''.join(random.choices(string.ascii_letters + string.digits, k = 12)),
                    "task_token": stepfunctions.JsonPath.task_token,
                    "task_details": stepfunctions.TaskInput.from_json_path_at("$.event_outputs")
                }
            ),
            integration_pattern=stepfunctions.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
            timeout=core.Duration.minutes(self.config['amiLifecycle']['amiPatchReceiverTimeout'])
        )

        ami_patch_step_10_result_choice = stepfunctions.Choice(
            self,
            "Was API Orchestrator AMI Patch notification successfull?",
            input_path="$",
            output_path="$"
        )

        ami_patch_step_success = stepfunctions.Succeed(
            self,
            "AMI Patch event success."
        )

        ami_patch_step_fail = stepfunctions.Fail(
            self,
            "AMI Patch event failure."
        )

        ami_patch_step_01_result_choice.when(stepfunctions.Condition.string_equals('$.patch_ami_operation.output.status', "ERROR"),
                                    ami_patch_step_fail).otherwise(ami_patch_step_02)

        ami_patch_step_02.next(ami_patch_step_02_result_choice)

        ami_patch_step_02_result_choice.when(stepfunctions.Condition.string_equals('$.patch_ami_operation.output.status', "ERROR"),
                            ami_patch_step_fail).otherwise(ami_patch_step_03)

        ami_patch_step_03.next(ami_patch_step_03_result_choice)

        ami_patch_step_03_result_choice.when(stepfunctions.Condition.string_equals('$.patch_ami_operation.output.status', "ERROR"),
                                    ami_patch_step_fail).otherwise(ami_patch_step_04)

        ami_patch_step_04.next(ami_patch_step_04_result_choice)

        ami_patch_step_04_result_choice.when(stepfunctions.Condition.string_equals('$.patch_ami_operation.output.status', "ERROR"),
                                    ami_patch_step_fail).otherwise(ami_patch_step_05)

        ami_patch_step_05.next(ami_patch_step_05_result_choice)

        ami_patch_step_05_result_choice.when(stepfunctions.Condition.string_equals('$.patch_ami_operation.output.status', "ERROR"),
                                    ami_patch_step_fail).otherwise(ami_patch_step_06)

        ami_patch_step_06.next(ami_patch_step_06_result_choice)

        ami_patch_step_06_result_choice.when(stepfunctions.Condition.string_equals('$.patch_ami_operation.output.status', "ERROR"),
                                    ami_patch_step_fail).otherwise(ami_patch_step_06_poll_choice)

        ami_patch_step_06_poll_choice.when(stepfunctions.Condition.string_equals('$.patch_ami_operation.output.ami_state', "AVAILABLE"),
                            ami_patch_step_07).otherwise(ami_patch_step_06_wait)

        ami_patch_step_06_wait.next(ami_patch_step_06)

        ami_patch_step_07.next(ami_patch_step_07_result_choice)

        ami_patch_step_07_result_choice.when(stepfunctions.Condition.string_equals('$.patch_ami_operation.output.status', "ERROR"),
                            ami_patch_step_fail).otherwise(ami_patch_step_08)

        ami_patch_step_08.next(ami_patch_step_08_result_choice)

        ami_patch_step_08_result_choice.when(stepfunctions.Condition.string_equals('$.patch_ami_operation.output.status', "ERROR"),
                            ami_patch_step_fail).otherwise(ami_patch_step_09)

        ami_patch_step_09.next(ami_patch_step_10_send_notification)

        ami_patch_step_10_send_notification.next(ami_patch_step_10_result_choice)

        ami_patch_step_10_result_choice.when(stepfunctions.Condition.string_equals('$.receiver_status', "ERROR"),
                                    ami_patch_step_fail).otherwise(ami_patch_step_success)                

        # step functions state machine
        ami_patch_state_machine = stepfunctions.StateMachine(
            self, 
            f"LifeCycleAmiPatchStateMachineName",
            timeout=core.Duration.minutes(self.config['amiLifecycle']['stateMachines']['amiPatchEventStateMachineTimeoutMins']),
            definition=ami_patch_step_01.next(ami_patch_step_01_result_choice),
            logs=stepfunctions.LogOptions(
                destination=patch_ami_state_machine_log_group,
                level=stepfunctions.LogLevel.ALL
            )
        )

        # export the arn of the ami build state machine which will be consumed by other processes
        core.CfnOutput(
            self,
            f"LifeCycleAmiPatchStateMachineNameOutput",
            value=ami_patch_state_machine.state_machine_arn,
            description="AMI Lifecycle AMI Patch Event State Machine"
        ).override_logical_id(CdkConstants.AMILIFECYCLE_AMI_PATCH_STATEMACHINE_NAME)


        ##########################################################
        # </END> AMI PATCH LIFECYCLE
        ##########################################################

        ##########################################################
        # </START> AMI MARK FOR PRODUCTION LIFECYCLE
        ##########################################################

        ami_backup_bucket = s3.Bucket(
            self, 
            "ami-backup-bucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            removal_policy=core.RemovalPolicy.DESTROY,
            public_read_access=False,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True
        )

        # define lamnbda functions
        mark_for_production_entry_point_lambda = self.get_mark_for_production_entry_point_lambda()
        mark_for_production_backup_lambda = self.get_mark_for_production_backup_lambda(ami_backup_bucket.bucket_name)
        mark_for_production_poll_backup_status_lambda = self.get_mark_for_production_backup_status_lambda()
        mark_for_production_notify_lambda = self.get_mark_for_production_notify_lambda()

        # grant lambdas access to the orchestrator key
        self.ami_orchestrator_key.grant_encrypt_decrypt(mark_for_production_entry_point_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(mark_for_production_backup_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(mark_for_production_poll_backup_status_lambda)
        self.ami_orchestrator_key.grant_encrypt_decrypt(mark_for_production_notify_lambda)

        self.ami_creation_receiver_queue.grant_send_messages(mark_for_production_notify_lambda)
        self.ami_patch_receiver_queue.grant_send_messages(mark_for_production_notify_lambda)
    
        # create log group for State Machine with 14 day retention period
        mark_for_production_state_machine_log_group = logs.LogGroup(
            self, 'AmiLcBackupStateMachineLogGroup',
            log_group_name='/aws/vendedlogs/states/amilifecycle/mark-for-production',
            removal_policy=core.RemovalPolicy.DESTROY
        )

        mark_for_production_step_01 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Mark For Production Entry Point",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=mark_for_production_entry_point_lambda
        )

        mark_for_production_step_02 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Execute AMI Backup process.",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=mark_for_production_backup_lambda
        )

        mark_for_production_step_02_result_choice = stepfunctions.Choice(
            self,
            "Was AMI Backup process launched successfull?",
            input_path="$",
            output_path="$"
        )

        mark_for_production_step_03 = stepfunctions_tasks.LambdaInvoke(
            self,
            "Poll AMI Backup Status until status is Completed",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=mark_for_production_poll_backup_status_lambda
        )

        mark_for_production_step_03_result_choice = stepfunctions.Choice(
            self,
            "Did AMI backup status request complete successfully?",
            input_path="$",
            output_path="$"
        )

        mark_for_production_step_03_poll_choice = stepfunctions.Choice(
            self,
            "Has AMI Backup completed?",
            input_path="$",
            output_path="$"
        )

        mark_for_production_step_03_wait = stepfunctions.Wait(
            self,
            "Wait to recheck if AMI Backup status is COMPLETED",
            time=stepfunctions.WaitTime.duration(core.Duration.minutes(3))
        )

        mark_for_production_step_04 = stepfunctions_tasks.LambdaInvoke(
            self,
            f"Notify Mark For Production results to ReceiverQueue",
            input_path="$",
            output_path="$.Payload.body",
            lambda_function=mark_for_production_notify_lambda
        )

        mark_for_production_step_04_result_choice = stepfunctions.Choice(
            self,
            "Was Mark For Production result notification successfull?",
            input_path="$",
            output_path="$"
        )

        mark_for_production_step_success = stepfunctions.Succeed(
            self,
            "Mark For Production event success."
        )

        mark_for_production_step_fail = stepfunctions.Fail(
            self,
            "Mark For Production event failure."
        )

        mark_for_production_step_02.next(mark_for_production_step_02_result_choice)

        mark_for_production_step_02_result_choice.when(stepfunctions.Condition.string_equals('$.mark_for_production_operation.output.status', "ERROR"),
                            mark_for_production_step_fail).otherwise(mark_for_production_step_03)

        mark_for_production_step_03.next(mark_for_production_step_03_result_choice)

        mark_for_production_step_03_result_choice.when(stepfunctions.Condition.string_equals('$.mark_for_production_operation.output.status', "ERROR"),
                            mark_for_production_step_fail).otherwise(mark_for_production_step_03_poll_choice)

        mark_for_production_step_03_poll_choice.when(stepfunctions.Condition.string_equals('$.mark_for_production_operation.output.ami_backup_state', "COMPLETED"),
                            mark_for_production_step_04).otherwise(mark_for_production_step_03_wait)

        mark_for_production_step_03_wait.next(mark_for_production_step_03)

        mark_for_production_step_04.next(mark_for_production_step_04_result_choice)

        mark_for_production_step_04_result_choice.when(stepfunctions.Condition.string_equals('$.mark_for_production_operation.output.status', "ERROR"),
                                    mark_for_production_step_fail).otherwise(mark_for_production_step_success)


        # step functions state machine
        mark_for_production_state_machine = stepfunctions.StateMachine(
            self, 
            f"LifeCycleMarkForProductionStateMachineName",
            timeout=core.Duration.minutes(self.config['amiLifecycle']['stateMachines']['markForProductionEventStateMachineTimeoutMins']),
            definition=mark_for_production_step_01.next(mark_for_production_step_02),
            logs=stepfunctions.LogOptions(
                destination=mark_for_production_state_machine_log_group,
                level=stepfunctions.LogLevel.ALL
            )
        )

        # export the arn of the state machine which will be consumed by other processes
        core.CfnOutput(
            self,
           f"LifeCycleMarkForProductionStateMachineArnOuput",
            value=mark_for_production_state_machine.state_machine_arn,
            description="AMI Lifecycle Mark For Production Event State Machine",
        ).override_logical_id(CdkConstants.AMILIFECYCLE_MARK_FOR_PRODUCTION_STATEMACHINE_NAME)

        core.CfnOutput(
            self,
            f"AmiBackupS3BucketExport",
            value=ami_backup_bucket.bucket_name
        ).override_logical_id(CdkConstants.AMILIFECYCLE_AMI_BACKUP_BUCKET)

        ##########################################################
        # </END> AMI MARK FOR PRODUCTION LIFECYCLE
        ##########################################################


        ##########################################################
        ##########################################################
        ##########################################################
        # </END> AMI Lifecycle
        ##########################################################
        ##########################################################
        ##########################################################


    ##########################################################
    ##########################################################
    # <START> AMI Orchestrator Lambdas and Roles
    ##########################################################
    ##########################################################

    ##########################################################
    # <START> Define reusable orchestrator lambda roles
    ##########################################################


    def get_assume_ami_tagger_role_policy(self) -> iam.PolicyStatement:
        distribution_accounts = [core.Aws.ACCOUNT_ID]
        resource_definitions = []
        for distribution_account in distribution_accounts:
            resource_definitions.append(f"arn:aws:iam::{distribution_account}:role/{self.config['amiLifecycle']['amiTagger']['taggerRole']}")
        
        return iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=resource_definitions,
                actions=[
                    "sts:AssumeRole"
                ]
            )


    def get_ami_tags_read_only_role_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=[f"*"],
                actions=[
                    "ec2:DescribeTags",
                    "ec2:DescribeImageAttribute",
                    "ec2:DescribeImages"
                ]
            )


    def get_ami_tags_write_role_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=[f"*"],
                actions=[
                    "ec2:DeleteTags",
                    "ec2:CreateTags",
                    "ec2:RegisterImage",
                    "ec2:ModifyImageAttribute"
                ]
            )

    

    def get_sns_subscribe_publish_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[
                        self.notification_topic.topic_arn,
                        self.reconciliation_topic.topic_arn
                    ],
                    actions=[
                        "sns:Publish",
                        "sns:Subscribe",
                        "sns:SetSubscriptionAttributes",
                        "sns:Unsubscribe",
                        "sns:ListSubscriptionsByTopic",
                        "sns:GetSubscriptionAttributes"
                    ]
                )

    def get_dynamob_db_rw_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[
                        self.ami_lifecycle_table.table_arn,
                        self.ami_lookup_table.table_arn,
                        self.ami_semver_seed_table.table_arn,
                        f"{self.ami_lifecycle_table.table_arn}/index/*",
                        f"{self.ami_lookup_table.table_arn}/index/*",
                        f"{self.ami_semver_seed_table.table_arn}/index/*"
                    ],
                    actions=[
                        "dynamodb:DeleteItem",
                        "dynamodb:GetItem",
                        "dynamodb:PutItem",
                        "dynamodb:Query",
                        "dynamodb:Scan",
                        "dynamodb:UpdateItem"
                    ]
                )

    def get_cloudwatch_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=["*"],
                    actions=[
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "logs:ListLogDeliveries",
                        "logs:DescribeLogStreams"
                    ]
                )

    def get_secretsmanager_read_only_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:*"],
                    actions=[
                        "secretsmanager:GetSecretValue"
                    ]
                )

    def get_api_gateway_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=[
                    "arn:aws:apigateway:*::/apis/*",
                    "arn:aws:apigateway:*::/apis"
                ],
                actions=[
                    "apigateway:GET"
                ]
            )

    def get_orchestrator_step_functions_execution_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=["*"],
                    actions=[
                        "states:SendTaskSuccess",
                        "states:SendTaskFailure",
                        "states:DescribeExecution",
                        "states:GetExecutionHistory",
                        "states:StartExecution",
                        "states:SendTaskHeartbeat"
                    ]
                )


    def get_lambda_execution_role(self, role_id) -> iam.Role:
        return iam.Role(
                    scope=self,
                    id=role_id,
                    assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
                    managed_policies=[
                        iam.ManagedPolicy.from_aws_managed_policy_name(
                            "service-role/AWSLambdaBasicExecutionRole"
                        )
                    ]
                )


    ##########################################################
    # </END> Define reusable orchestrator lambda roles
    ##########################################################


    ##########################################################
    # <START> Define common orchestrator envars and role combos
    ##########################################################

    def get_common_orchestrator_envvars(self) -> dict:

        api_keys_internal = self.config['amiLifecycle']['api']['security']['api_keys']['internal']
        api_keys_external = self.config['amiLifecycle']['api']['security']['api_keys']['external']

        return {
                "STACK_TAG": CdkUtils.stack_tag,
                "AMI_LIFECYCLE_STATE_TABLENAME": self.ami_lifecycle_table.table_name,
                "AMI_LOOKUP_TABLENAME": self.ami_lookup_table.table_name,
                "AMI_SEMVER_SEED_TABLENAME": self.ami_semver_seed_table.table_name,
                "DEFAULT_AMI_SEMVER_SEED": self.config['amiLifecycle']['defaultAmiSemverSeed'],
                "API_NAME": f"{self.config['amiLifecycle']['api']['apiName']}",
                "API_STAGE_NAME": self.config['amiLifecycle']['api']['apiStageName'],
                "ACCOUNT_ID": core.Aws.ACCOUNT_ID,
                "TOOLING_ACCOUNT_ID": core.Aws.ACCOUNT_ID,
                "SHARED_SERVICES_ACCOUNT_ID": core.Aws.ACCOUNT_ID,
                "DISTRIBUTION_REGIONS": core.Aws.REGION,
                "DISTRIBUTION_ACCOUNTS": core.Aws.ACCOUNT_ID,
                "AMI_TAGGER_ROLE_NAME": f"{self.config['amiLifecycle']['amiTagger']['taggerRole']}",
                "SNS_TOPIC_ARN": self.notification_topic.topic_arn,
                "AMI_CREATION_POST_SECRET_NAME": api_keys_internal['ami_creation_post_secret_name'],
                "AMI_CREATION_PUT_SECRET_NAME": api_keys_internal['ami_creation_put_secret_name'],
                "AMI_CREATION_STATUS_SECRET_NAME": api_keys_internal['ami_creation_status_secret_name'],
                "AMI_CREATION_QA_CERTIFY_SECRET_NAME": api_keys_external['ami_creation_qa_certification_secret_name'],
                "AMI_CREATION_MARK_FOR_PRODUCTION_SECRET_NAME": api_keys_external['ami_creation_mark_for_production_secret_name'],
                "AMI_PATCH_MARK_FOR_PRODUCTION_SECRET_NAME": api_keys_external['ami_patch_mark_for_production_secret_name'],
                "AMI_CREATION_TIMELINE_SECRET_NAME": api_keys_internal['ami_creation_timeline_secret_name'],
                "AMI_PATCH_POST_SECRET_NAME": api_keys_internal['ami_patch_post_secret_name'],
                "AMI_PATCH_PUT_SECRET_NAME": api_keys_internal['ami_patch_put_secret_name'],
                "AMI_PATCH_TIMELINE_SECRET_NAME": api_keys_internal['ami_patch_timeline_secret_name'],
                "AMI_CREATION_RECEIVER_SECRET_NAME": api_keys_internal['ami_creation_receiver_secret_name'],
                "AMI_PATCH_RECEIVER_SECRET_NAME": api_keys_internal['ami_patch_receiver_secret_name'],
                "AMI_ERROR_RECEIVER_SECRET_NAME": api_keys_internal['ami_error_receiver_secret_name'],
                "IMAGEBUILDER_PIPELINE_ARN": CdkConstants.IMAGEBUILDER_PIPELINE_ARN,
                "AMI_BUILD_STATEMACHINE_NAME": CdkConstants.AMILIFECYCLE_AMI_BUILD_STATEMACHINE_NAME,
                "SMOKE_TESTS_STATEMACHINE_NAME": CdkConstants.AMILIFECYCLE_SMOKE_TESTS_STATEMACHINE_NAME,
                "VULNERABILITY_SCANS_STATEMACHINE_NAME": CdkConstants.AMILIFECYCLE_VULNERABILITY_SCANS_STATEMACHINE_NAME,
                "QA_CERTIFICATION_STATEMACHINE_NAME": CdkConstants.AMILIFECYCLE_QA_CERTIFICATION_STATEMACHINE_NAME,
                "AMI_PATCH_STATEMACHINE_NAME": CdkConstants.AMILIFECYCLE_AMI_PATCH_STATEMACHINE_NAME,
                "MARK_FOR_PRODUCTION_STATEMACHINE_NAME": CdkConstants.AMILIFECYCLE_MARK_FOR_PRODUCTION_STATEMACHINE_NAME,
                "STACK_NAME_IMAGEBUILDER": self.config['amiLifecycle']['cfnStackNameImageBuilder'],
                "STACK_NAME_AMI_LIFECYCLE": self.config['amiLifecycle']['cfnStackNameAmiLifecycle'],
                "STATE_MACHINE_MAX_WAIT_TIME": str(self.config['amiLifecycle']['stateMachineMaxWaitTime']),
                "EVENT_NOTIFICATION_LAMBDA_ARN": self.event_notification_lambda.function_arn
            }


    def set_common_orchestrator_roles(self, lambda_role: iam.Role) -> None:
        lambda_role.add_to_policy(self.get_dynamob_db_rw_policy())
        lambda_role.add_to_policy(self.get_orchestrator_step_functions_execution_policy())
        lambda_role.add_to_policy(self.get_cloudwatch_policy())
        lambda_role.add_to_policy(self.get_sns_subscribe_publish_policy())
        lambda_role.add_to_policy(self.get_api_gateway_policy())
        lambda_role.add_to_policy(self.get_assume_ami_tagger_role_policy())
        lambda_role.add_to_policy(self.get_ami_tags_read_only_role_policy())
        lambda_role.add_to_policy(self.get_ami_tags_write_role_policy())
        lambda_role.add_to_policy(self.get_secretsmanager_read_only_policy())
        lambda_role.add_to_policy(self.get_cloudformation_read_only_policy())


    ##########################################################
    # </END> Define common orchestrator envars and role combos
    ##########################################################


    ##########################################################
    # <START> Define API lambdas
    ##########################################################

    def get_ami_lifecycle_get_status_by_lifecycle_id_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"ApiGetStatusByLifecycleIdLambdaRole")
        self.set_common_orchestrator_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id="ApiGetStatusByLifecycleIdLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_orchestrator"),
            handler="api.ami_lifecycle_get_status_by_lifecycle_id.lambda_handler",
            role=lambda_role,
            environment=self.get_common_orchestrator_envvars(),
            layers=[self.ami_orchestrator_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_lifecycle_get_status_by_stack_tag_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"ApiGetStatusByStackTagLambdaRole")
        self.set_common_orchestrator_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id="ApiGetStatusByStackTagLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_orchestrator"),
            handler="api.ami_lifecycle_get_status.lambda_handler",
            role=lambda_role,
            environment=self.get_common_orchestrator_envvars(),
            layers=[self.ami_orchestrator_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda


    
    def get_ami_creation_lifecycle_post_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"ApiCreateLifecycleLambdaRole")
        self.set_common_orchestrator_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id="ApiCreateLifecycleLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_orchestrator"),
            handler="api.ami_creation_lifecycle_post.lambda_handler",
            role=lambda_role,
            environment=self.get_common_orchestrator_envvars(),
            layers=[self.ami_orchestrator_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_creation_lifecycle_put_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"ApiCreateUpdateLifecycleLambdaRole")
        self.set_common_orchestrator_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id="ApiCreateUpdateLifecycleLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_orchestrator"),
            handler="api.ami_creation_lifecycle_put.lambda_handler",
            role=lambda_role,
            environment=self.get_common_orchestrator_envvars(),
            layers=[self.ami_orchestrator_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_creation_qa_certify_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"ApiCreateQACertifyLifecycleLambdaRole")
        self.set_common_orchestrator_roles(lambda_role)
        lambda_role.add_to_policy(self.get_sqs_send_message_policy())

        env_vars = {}
        env_vars = self.get_common_orchestrator_envvars()
        env_vars['RECEIVER_QUEUE_URL'] = self.ami_creation_receiver_queue.queue_url

        _lambda = aws_lambda.Function(
            scope=self,
            id="ApiCreateQACertifyLifecycleLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_orchestrator"),
            handler="api.ami_creation_qa_certification_post.lambda_handler",
            role=lambda_role,
            environment=env_vars,
            layers=[self.ami_orchestrator_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda


    def get_ami_creation_mark_for_production_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"ApiCreateMarkForProdLifecycleLambdaRole")
        self.set_common_orchestrator_roles(lambda_role)
        lambda_role.add_to_policy(self.get_sqs_send_message_policy())

        env_vars = {}
        env_vars = self.get_common_orchestrator_envvars()
        env_vars['RECEIVER_QUEUE_URL'] = self.ami_creation_receiver_queue.queue_url

        _lambda = aws_lambda.Function(
            scope=self,
            id="ApiCreateMarkForProdLifecycleLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_orchestrator"),
            handler="api.ami_creation_mark_for_production_post.lambda_handler",
            role=lambda_role,
            environment=env_vars,
            layers=[self.ami_orchestrator_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_patch_mark_for_production_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"ApiPatchMarkForProdLifecycleLambdaRole")
        self.set_common_orchestrator_roles(lambda_role)
        lambda_role.add_to_policy(self.get_sqs_send_message_policy())

        env_vars = {}
        env_vars = self.get_common_orchestrator_envvars()
        env_vars['RECEIVER_QUEUE_URL'] = self.ami_patch_receiver_queue.queue_url

        _lambda = aws_lambda.Function(
            scope=self,
            id="ApiPatchMarkForProdLifecycleLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_orchestrator"),
            handler="api.ami_patch_mark_for_production_post.lambda_handler",
            role=lambda_role,
            environment=env_vars,
            layers=[self.ami_orchestrator_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda


    def get_ami_creation_timeline_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"ApiCreateTimelineLambdaRole")
        self.set_common_orchestrator_roles(lambda_role)
        lambda_role.add_to_policy(self.get_sqs_send_message_policy())

        _lambda = aws_lambda.Function(
            scope=self,
            id="ApiCreateTimelineLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_orchestrator"),
            handler="api.ami_creation_get_timeline_by_lifecycle_id.lambda_handler",
            role=lambda_role,
            environment=self.get_common_orchestrator_envvars(),
            layers=[self.ami_orchestrator_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_creation_receiver_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"ApiCreateReceiverLambdaRole")
        self.set_common_orchestrator_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id="ApiCreateReceiverLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_orchestrator"),
            handler="api.receivers.ami_creation_receiver.lambda_handler",
            role=lambda_role,
            environment=self.get_common_orchestrator_envvars(),
            layers=[self.ami_orchestrator_deps_layer],
            timeout=core.Duration.minutes(15),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_patch_lifecycle_post_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"ApiPatchLifecycleLambdaRole")
        self.set_common_orchestrator_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id="ApiPatchLifecycleLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_orchestrator"),
            handler="api.ami_patch_lifecycle_post.lambda_handler",
            role=lambda_role,
            environment=self.get_common_orchestrator_envvars(),
            layers=[self.ami_orchestrator_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_patch_lifecycle_put_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"ApiPatchUpdateLifecycleLambdaRole")
        self.set_common_orchestrator_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id="ApiPatchUpdateLifecycleLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_orchestrator"),
            handler="api.ami_patch_lifecycle_put.lambda_handler",
            role=lambda_role,
            environment=self.get_common_orchestrator_envvars(),
            layers=[self.ami_orchestrator_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_patch_timeline_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"ApiPatchTimelineLambdaRole")
        self.set_common_orchestrator_roles(lambda_role)
        lambda_role.add_to_policy(self.get_sqs_send_message_policy())

        _lambda = aws_lambda.Function(
            scope=self,
            id="ApiPatchTimelineLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_orchestrator"),
            handler="api.ami_patch_get_timeline_by_lifecycle_id.lambda_handler",
            role=lambda_role,
            environment=self.get_common_orchestrator_envvars(),
            layers=[self.ami_orchestrator_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_patch_receiver_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"ApiPatchReceiverLambdaRole")
        self.set_common_orchestrator_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id="ApiPatchReceiverLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_orchestrator"),
            handler="api.receivers.ami_patch_receiver.lambda_handler",
            role=lambda_role,
            environment=self.get_common_orchestrator_envvars(),
            layers=[self.ami_orchestrator_deps_layer],
            timeout=core.Duration.minutes(15),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_error_receiver_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"ApiErrorReceiverLambdaRole")
        self.set_common_orchestrator_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id="ApiErrorReceiverLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_orchestrator"),
            handler="api.receivers.ami_error_receiver.lambda_handler",
            role=lambda_role,
            environment=self.get_common_orchestrator_envvars(),
            layers=[self.ami_orchestrator_deps_layer],
            timeout=core.Duration.minutes(15),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_reconciler_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role("ApiReconcilerLambdaRole")
        self.set_common_orchestrator_roles(lambda_role)

        env_vars = self.get_common_orchestrator_envvars()
        env_vars['RECONCILER_SNS_TOPIC_ARN'] = self.reconciliation_topic.topic_arn

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"ApiReconcilerLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_orchestrator"),
            handler="api.reconciler.reconciler.lambda_handler",
            role=lambda_role,
            environment=env_vars,
            layers=[self.ami_orchestrator_deps_layer],
            timeout=core.Duration.minutes(15),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda


    ##########################################################
    # </END> Define API lambdas
    ##########################################################

    ##########################################################
    ##########################################################
    # </END> AMI Orchestrator Lambdas and Roles
    ##########################################################
    ##########################################################


    ##########################################################
    ##########################################################
    # <START> AMI Lifecycle Lambdas and Roles
    ##########################################################
    ##########################################################


    ##########################################################
    # <START> Define reusable lifecycle lambda envvars
    ##########################################################

    def get_common_lifecycle_envvars(self) -> dict:
        api_keys_internal = self.config['amiLifecycle']['api']['security']['api_keys']['internal']
        api_keys_external = self.config['amiLifecycle']['api']['security']['api_keys']['external']
        return {
            "STACK_TAG": CdkUtils.stack_tag,
            "STACK_PREFIX_AMI_MANAGER": self.config['amiLifecycle']['cfnStackPrefixManager'],
            "AMI_CREATION_RECEIVER_SECRET_NAME": api_keys_internal['ami_creation_receiver_secret_name'],
            "AMI_ERROR_RECEIVER_SECRET_NAME": api_keys_internal['ami_error_receiver_secret_name'],
            "AMI_PATCH_RECEIVER_SECRET_NAME": api_keys_internal['ami_patch_receiver_secret_name'],
            "AMI_CREATION_QA_CERTIFY_SECRET_NAME": api_keys_external['ami_creation_qa_certification_secret_name'],
            "NOTIFICATION_SNS_TOPIC_ARN": self.notification_topic.topic_arn,
            "API_ERROR_QUEUE_URL": self.ami_error_receiver_queue.queue_url
        }

    ##########################################################
    # </END> Define reusable lifecycle lambda envvars
    ##########################################################

    ##########################################################
    # <START> Define reusable lifecycle lambda roles
    ##########################################################

    def get_cloudwatch_logs_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=["*"],
                    actions=[
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents"
                    ]
                )

    def get_cloudwatch_put_metrics_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=["*"],
                    actions=[
                        "cloudwatch:PutMetricData"
                    ]
                )

    def get_sns_publish_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[
                        self.notification_topic.topic_arn,
                        self.imagebuilder_topic_arn
                    ],
                    actions=[
                        "sns:Publish"
                    ]
                )

    def get_sqs_send_message_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[
                        self.ami_creation_receiver_queue.queue_arn,
                        self.ami_error_receiver_queue.queue_arn,
                        self.ami_patch_receiver_queue.queue_arn
                    ],
                    actions=[
                        "sqs:SendMessage"
                    ]
                )

    def get_cloudformation_read_only_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=["*"],
                actions=[
                    "cloudformation:DescribeStacks"
                ]
            )

    def get_imagebuilder_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=[
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:image/*/*/*",
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:image-pipeline/*"
                ],
                actions=[
                    "imagebuilder:GetImage",
                    "imagebuilder:ListImagePipelineImages",
                    "imagebuilder:StartImagePipelineExecution",

                ]
            )

    def get_create_imagebuilder_recipe_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=[
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:image/*/*/*",
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:image-pipeline/*",
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:image-recipe/*",
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:component/*"
                ],
                actions=[
                    "imagebuilder:CreateImageRecipe",
                    "ec2:DescribeImages",
                    "iam:CreateServiceLinkedRole",
                    "imagebuilder:GetComponent",
                    "imagebuilder:GetImage",
                    "imagebuilder:TagResource"
                ]
            )


    def get_ec2_describe_images_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=["*"],
            actions=[
                "ec2:DescribeImages"
            ]
        )

    def get_create_imagebuilder_pipeline_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=[
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:image/*/*/*",
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:image-pipeline/*",
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:infrastructure-configuration/*",
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:distribution-configuration/*",
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:image-recipe/*/*",
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:component/*"
                ],
                actions=[
                    "imagebuilder:CreateImagePipeline",
                    "imagebuilder:GetContainerRecipe",
                    "imagebuilder:GetImageRecipe",
                    "imagebuilder:TagResource",
                    "imagebuilder:CreateDistributionConfiguration",
                    "imagebuilder:CreateInfrastructureConfiguration",
                    "imagebuilder:GetInfrastructureConfiguration",
                    "imagebuilder:GetDistributionConfiguration"
                ]
            )

    def get_image_builder_iam_role_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=[
                "*"
            ],
            actions=[
                "iam:PassRole",
                "iam:CreateServiceLinkedRole"
            ]
        )

    def get_image_builder_delete_iam_role_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=[
                "*"
            ],
            actions=[
                "iam:PassRole",
                "iam:DeleteServiceLinkedRole"
            ]
        )


    def get_create_imagebuilder_component_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=[
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:image/*/*/*",
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:image-pipeline/*",
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:component/*"
                ],
                actions=[
                    "imagebuilder:CreateComponent",
                    "iam:CreateServiceLinkedRole",
                    "imagebuilder:TagResource",
                    "kms:Encrypt",
                    "kms:GenerateDataKey",
                    "kms:GenerateDataKeyWithoutPlaintext"
                ]
            )

    def get_delete_imagebuilder_pipeline_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=[
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:image/*/*/*",
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:image-pipeline/*",
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:infrastructure-configuration/*",
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:distribution-configuration/*",
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:image-recipe/*/*",
                    f"arn:aws:imagebuilder:{self.region}:{self.account}:component/*"
                ],
                actions=[
                    "imagebuilder:DeleteImagePipeline",
                    "imagebuilder:DeleteComponent",
                    "imagebuilder:DeleteImageRecipe",
                    "imagebuilder:DeleteDistributionConfiguration",
                    "imagebuilder:DeleteInfrastructureConfiguration",
                    "imagebuilder:DeleteImage",
                    "imagebuilder:GetContainerRecipe",
                    "imagebuilder:GetImageRecipe",
                    "imagebuilder:TagResource",
                    "imagebuilder:GetInfrastructureConfiguration",
                    "imagebuilder:GetDistributionConfiguration",
                    "imagebuilder:GetComponent",
                    "imagebuilder:GetImage",
                    "ec2:DescribeImages",
                    "kms:Encrypt",
                    "kms:GenerateDataKey",
                    "kms:GenerateDataKeyWithoutPlaintext"
                ]
            )

    def get_lifecycle_step_functions_execution_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=["*"],
                    actions=[
                        "states:SendTaskSuccess",
                        "states:SendTaskFailure",
                        "states:SendTaskHeartbeat"
                    ]
                )

    def get_ec2_run_instances_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=["*"],
                    actions=[
                        "ec2:*"
                    ]
                )

    def get_ec2_terminate_instances_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[f"arn:aws:ec2:{self.region}:{self.account}:instance/*"],
                    actions=[
                        "ec2:TerminateInstances"
                    ]
                )


    def get_ec2_describe_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[f"*"],
                    actions=[
                        "ec2:Describe*"
                    ]
                )


    def get_vmdk_export_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[f"*"],
                    actions=[
                        "ec2:CopySnapshot",
                        "ec2:Describe*",
                        "ec2:ModifySnapshotAttribute",
                        "ec2:RegisterImage",
                        "ec2:CreateTags",
                        "ec2:ExportImage"
                    ]
                )


    def get_vmdk_poll_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=["*"],
            actions=[
                "ec2:Describe*",
                "ec2:ModifyImageAttribute",
                "ec2:ReportInstanceStatus",
                "ec2:DescribeExportImageTasks",
                "ec2:DescribeExportTasks",
                "ec2:CreateTags",
                "ec2:ExportImage"
            ],
        )

    def get_generate_url_policy(self, vmdk_export_bucket_arn: str) -> iam.PolicyStatement:
        return iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=[
                vmdk_export_bucket_arn,
                f"{vmdk_export_bucket_arn}/*"
            ],
            actions=[
                "s3:PutObject",
                "s3:GetObject"
            ],
        )


    def get_iam_pass_role_policy(self, tests_role: iam.Role) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=[tests_role.role_arn],
                    actions=[
                        "iam:PassRole"
                    ]
                )

    def get_inspector2_list_coverage_role_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=["*"],
                    actions=[
                        "inspector2:ListCoverage"
                    ]
                )

    def get_inspector2_create_findings_role_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=["*"],
                    actions=[
                        "inspector2:ListFindings",
                        "inspector2:CreateFindingsReport"
                    ]
                )

    def get_inspector2_list_account_permissions(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=["*"],
            actions=[
                "inspector2:ListAccountPermissions"
            ]
        )

    def get_vmdk_export_bucket_policy(self, vmdk_export_bucket_arn: str) -> iam.PolicyStatement:
        return iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=[
                vmdk_export_bucket_arn,
                f"{vmdk_export_bucket_arn}/*"
            ],
            actions=[
                "s3:GetObject*",
                "s3:GetBucket*",
                "s3:List*",
                "s3:DeleteObject*",
                "s3:PutObject",
                "s3:Abort*"
            ]
        )

    def get_ami_backup_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=['*'],
            actions=[
                "ec2:DescribeExportImageTasks",
                "ec2:CreateRestoreImageTask",
                "ec2:DescribeImportImageTasks",
                "ec2:CreateStoreImageTask",
                "ec2:DescribeStoreImageTasks",
                "s3:DeleteObject",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:PutObject",
                "s3:AbortMultipartUpload",
                "s3:PutBucketTagging",
                "s3:PutObjectTagging",
                "ebs:CompleteSnapshot",
                "ebs:GetSnapshotBlock",
                "ebs:ListChangedBlocks",
                "ebs:ListSnapshotBlocks",
                "ebs:PutSnapshotBlock",
                "ebs:StartSnapshot",
                "ec2:GetEbsEncryptionByDefault",
                "ec2:DescribeTags",
                "ec2:CreateTags"
            ]
        )

    def get_ami_backup_status_policy(self) -> iam.PolicyStatement:
        return iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=['*'],
            actions=[
                "ec2:DescribeExportImageTasks",
                "ec2:CreateRestoreImageTask",
                "ec2:DescribeImportImageTasks",
                "ec2:CreateStoreImageTask",
                "ec2:DescribeStoreImageTasks",
                "s3:DeleteObject",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:PutObject",
                "s3:AbortMultipartUpload",
                "s3:PutBucketTagging",
                "s3:PutObjectTagging",
                "ebs:CompleteSnapshot",
                "ebs:GetSnapshotBlock",
                "ebs:ListChangedBlocks",
                "ebs:ListSnapshotBlocks",
                "ebs:PutSnapshotBlock",
                "ebs:StartSnapshot",
                "ec2:GetEbsEncryptionByDefault",
                "ec2:DescribeTags",
                "ec2:CreateTags"
            ]
        )

    def set_common_lifecycle_roles(self, lambda_role) -> None:
        lambda_role.add_to_policy(self.get_cloudwatch_logs_policy())
        lambda_role.add_to_policy(self.get_cloudformation_read_only_policy())
        lambda_role.add_to_policy(self.get_imagebuilder_policy())
        lambda_role.add_to_policy(self.get_secretsmanager_read_only_policy())
        lambda_role.add_to_policy(self.get_sns_publish_policy())
        lambda_role.add_to_policy(self.get_sqs_send_message_policy())

    ##########################################################
    # </END> Define reusable lifecycle lambda roles
    ##########################################################


    ##########################################################
    # <START> Define BUILD AMI Lifecycle lambdas
    ##########################################################

    def get_ami_build_entry_point_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcBuildEntryPointLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcBuildEntryPointLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.ami_build.entry_point.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_build_poll_ami_status_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcBuildPollAmiStatusLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcBuildPollAmiStatusLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.ami_build.poll_ami_status.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_build_ami_details_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcBuildAmiDetailsLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcBuildAmiDetailsLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.ami_build.get_ami_details.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_build_notify_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcBuildNotifyLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcBuildNotifyLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.ami_build.notify.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda


    ##########################################################
    # </END> Define BUILD AMI Lifecycle lambdas
    ##########################################################


    ##########################################################
    # <START> Define SMOKE TESTS Lifecycle lambdas
    ##########################################################

    def get_smoke_tests_entry_point_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcSmokeTestsEntryPointLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcSmokeTestsEntryPointLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.smoke_tests.entry_point.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_smoke_tests_executor_lambda(
            self,
            vpc: ec2.Vpc,
            security_group: ec2.SecurityGroup,
            s3_object_url,
            sqs_queue_url,
            log_group_name,
            ec2_instance_profile: iam.CfnInstanceProfile,
            tests_role: iam.Role
        ) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcSmokeTestsExecutorLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)
        lambda_role.add_to_policy(self.get_lifecycle_step_functions_execution_policy())
        lambda_role.add_to_policy(self.get_ec2_run_instances_policy())
        lambda_role.add_to_policy(self.get_iam_pass_role_policy(tests_role))

        env_vars = self.get_common_lifecycle_envvars()
        env_vars['TEST_CASE_ASSETS'] = s3_object_url
        env_vars['EBS_VOLUME_SIZE'] = str(self.config["imageBuilder"]["ebsVolumeSize"])
        env_vars['EC2_INSTANCE_TYPE'] = self.config["imageBuilder"]["instanceTypes"][0]
        env_vars['EC2_INSTANCE_PROFILE_ARN'] = ec2_instance_profile.attr_arn
        env_vars['SQS_QUEUE_URL'] = sqs_queue_url
        env_vars['LOG_GROUP_NAME'] = log_group_name
        env_vars['VPC_ID'] = vpc.vpc_id
        env_vars['SUBNET_ID'] = vpc.private_subnets[0].subnet_id
        env_vars['SECURITY_GROUP_ID']=security_group.security_group_id
        env_vars['SMOKE_TESTS_TIMEOUT']=str(self.config['amiLifecycle']['stateMachines']['smokeTestEventStateMachineSqsTimeoutMins'])

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcSmokeTestsExecutorLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.smoke_tests.smoketest_executor.lambda_handler",
            role=lambda_role,
            environment=env_vars,
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda


    def get_smoke_tests_tear_down_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcSmokeTestsTearDownLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)
        lambda_role.add_to_policy(self.get_ec2_terminate_instances_policy())

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcSmokeTestsTearDownLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.smoke_tests.tear_down.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_smoke_tests_notify_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcSmokeTestsNotifyLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)

        env_vars = self.get_common_lifecycle_envvars()
        env_vars['EVENT_RECEIVER_QUEUE_URL'] = self.ami_creation_receiver_queue.queue_url
        env_vars['PATCH_EVENT_RECEIVER_QUEUE_URL'] = self.ami_patch_receiver_queue.queue_url

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcSmokeTestsNotifyLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.smoke_tests.notify.lambda_handler",
            role=lambda_role,
            environment=env_vars,
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    ##########################################################
    # <START> Define SMOKE TESTS Lifecycle lambdas
    ##########################################################


    ##########################################################
    # <START> Define VULNERABILITY SCANS Lifecycle lambdas
    ##########################################################

    def get_vulnerability_scans_entry_point_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcVulnerabilityScansEntryPointLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)
        lambda_role.add_to_policy(self.get_inspector2_list_account_permissions())
        
        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcVulnerabilityScansEntryPointLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.vulnerability_scans.entry_point.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_vulnerability_scans_launch_instance_lambda(
            self,
            vpc: ec2.Vpc,
            security_group: ec2.SecurityGroup,
            ec2_instance_profile: iam.CfnInstanceProfile,
            tests_role: iam.Role
        ) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcVulnerabilityScansLaunchInstanceLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)
        lambda_role.add_to_policy(self.get_lifecycle_step_functions_execution_policy())
        lambda_role.add_to_policy(self.get_ec2_run_instances_policy())
        lambda_role.add_to_policy(self.get_iam_pass_role_policy(tests_role))

        env_vars = self.get_common_lifecycle_envvars()
        env_vars['EBS_VOLUME_SIZE'] = str(self.config["imageBuilder"]["ebsVolumeSize"])
        env_vars['EC2_INSTANCE_TYPE'] = self.config["imageBuilder"]["instanceTypes"][0]
        env_vars['EC2_INSTANCE_PROFILE_ARN'] = ec2_instance_profile.attr_arn
        env_vars['VPC_ID'] = vpc.vpc_id
        env_vars['SUBNET_ID'] = vpc.private_subnets[0].subnet_id
        env_vars['SECURITY_GROUP_ID']=security_group.security_group_id
       
        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcVulnerabilityScansLaunchInstanceLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.vulnerability_scans.launch_instance.lambda_handler",
            role=lambda_role,
            environment=env_vars,
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(10),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_vulnerability_scans_poll_status_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcVulnerabilityScansPollStatusLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)
        lambda_role.add_to_policy(self.get_inspector2_list_coverage_role_policy())

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcVulnerabilityScansPollStatusLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.vulnerability_scans.poll_scan_status.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_vulnerability_scans_findings_lambda(
            self,
            findings_bucket_name: str,
            vulnerability_scans_key_arn: str
        ) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcVulnerabilityScansFindingsLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)
        lambda_role.add_to_policy(self.get_inspector2_create_findings_role_policy())

        env_vars = self.get_common_lifecycle_envvars()
        env_vars['S3_BUCKET'] = findings_bucket_name
        env_vars['KMS_KEY_ARN'] = vulnerability_scans_key_arn

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcVulnerabilityScansFindingsLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.vulnerability_scans.get_scan_findings.lambda_handler",
            role=lambda_role,
            environment=env_vars,
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda


    def get_vulnerability_scans_tear_down_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcVulnerabilityScansTearDownLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)
        lambda_role.add_to_policy(self.get_ec2_terminate_instances_policy())

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcVulnerabilityScansTearDownLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.vulnerability_scans.tear_down.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_vulnerability_scans_publish_metrics_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcVulnerabilityScansPublishMetricsLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)
        lambda_role.add_to_policy(self.get_cloudwatch_put_metrics_policy())

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcVulnerabilityScansPublishMetricsLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.vulnerability_scans.publish_metric_data.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_vulnerability_scans_notify_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcVulnerabilityScansNotifyLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)

        env_vars = self.get_common_lifecycle_envvars()
        env_vars['EVENT_RECEIVER_QUEUE_URL'] = self.ami_creation_receiver_queue.queue_url
        env_vars['PATCH_EVENT_RECEIVER_QUEUE_URL'] = self.ami_patch_receiver_queue.queue_url

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcVulnerabilityScansNotifyLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.vulnerability_scans.notify.lambda_handler",
            role=lambda_role,
            environment=env_vars,
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    ##########################################################
    # </END> Define VULNERABILITY SCANS Lifecycle lambdas
    ##########################################################


    ##########################################################
    # <START> Define QA CERTIFICATION Lifecycle lambdas
    ##########################################################

    def get_qa_certification_entry_point_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcQACertifyEntryPointLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcQACertifyEntryPointLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.qa_certification.entry_point.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_qa_certification_poll_ami_status_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcQACertifyAmiStatusLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)
        lambda_role.add_to_policy(self.get_ec2_describe_policy())

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcQACertifyAmiStatusLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.qa_certification.poll_ami_status.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_qa_certification_vmdk_export_lambda(
            self,
            vmdk_export_bucket_arn: str
        ) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcQACertifyVmdkExportLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)
        lambda_role.add_to_policy(self.get_vmdk_export_policy())
        lambda_role.add_to_policy(self.get_vmdk_export_bucket_policy(vmdk_export_bucket_arn))

        env_vars = self.get_common_lifecycle_envvars()
        vmdk_export_bucket = s3.Bucket.from_bucket_arn(self, "vmdk-export-bucket-ref", bucket_arn=vmdk_export_bucket_arn)
        env_vars['EXPORT_BUCKET'] = vmdk_export_bucket.bucket_name
        env_vars['EXPORT_ROLE'] = self.vm_import_role.role_name

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcQACertifyVmdkExportLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.qa_certification.export_vmdk.lambda_handler",
            role=lambda_role,
            environment=env_vars,
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_qa_certification_poll_vmdk_status_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcQACertifyPollVmdkStatusLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)
        lambda_role.add_to_policy(self.get_vmdk_poll_policy())

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcQACertifyPollVmdkStatusLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.qa_certification.poll_vmdk_status.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_qa_certification_generate_url_lambda(
            self,
            vmdk_export_bucket_arn: str
        ) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcQACertifyGenerateUrlLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)
        lambda_role.add_to_policy(self.get_generate_url_policy(vmdk_export_bucket_arn))
        lambda_role.add_to_policy(self.get_ec2_describe_policy())
        lambda_role.add_to_policy(self.get_vmdk_export_bucket_policy(vmdk_export_bucket_arn))

        env_vars = self.get_common_lifecycle_envvars()
        env_vars['EXPORT_LINK_EXPIRY'] = str(self.config['amiLifecycle']['exportLinkExpiry'])

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcQACertifyGenerateUrlLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.qa_certification.generate_download_url.lambda_handler",
            role=lambda_role,
            environment=env_vars,
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_qa_certification_notify_external_qa_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcQACertifyNotifyQALambdaRole")
        self.set_common_lifecycle_roles(lambda_role)

        env_vars = self.get_common_lifecycle_envvars()
        env_vars['QA_SNS_TOPIC'] = self.qa_sns_topic.topic_arn
 
        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcQACertifyNotifyQALambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.qa_certification.notify_external_qa.lambda_handler",
            role=lambda_role,
            environment=env_vars,
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_qa_certification_notify_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcQACertifyNotifyLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcQACertifyNotifyLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.qa_certification.notify.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda


    ##########################################################
    # </END> Define QA CERTIFICATION Lifecycle lambdas
    ##########################################################


    ##########################################################
    # <START> Define PATCH AMI Lifecycle lambdas
    ##########################################################

    def get_ami_patch_entry_point_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcPatchEntryPointLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcPatchEntryPointLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.ami_patch.entry_point.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_patch_create_component_lambda(
            self,
            ami_orchestrator_key: kms.Key
        ) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcPatchCreateComponentLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)
        lambda_role.add_to_policy(self.get_create_imagebuilder_component_policy())

        env_vars = self.get_common_lifecycle_envvars()
        env_vars['KMS_KEY_ARN'] = ami_orchestrator_key.key_arn

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcPatchCreateComponentLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.ami_patch.create_component.lambda_handler",
            role=lambda_role,
            environment=env_vars,
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_patch_create_image_recipe_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcPatchCreateImageRecipeLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)
        lambda_role.add_to_policy(self.get_create_imagebuilder_recipe_policy())
        lambda_role.add_to_policy(self.get_ec2_describe_images_policy())

        env_vars = self.get_common_lifecycle_envvars()
        env_vars['EBS_VOLUME_SIZE'] = str(self.config["imageBuilder"]["ebsVolumeSize"])

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcPatchCreateImageRecipeLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.ami_patch.create_image_recipe.lambda_handler",
            role=lambda_role,
            environment=env_vars,
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_patch_create_imagepipeline_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcPatchCreateImagePipelineLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)
        lambda_role.add_to_policy(self.get_create_imagebuilder_pipeline_policy())
        lambda_role.add_to_policy(self.get_image_builder_iam_role_policy())

        env_vars = self.get_common_lifecycle_envvars()
        env_vars['PUBLISHING_ACCOUNT_IDS'] = core.Aws.ACCOUNT_ID
        env_vars['SHARING_ACCOUNT_IDS'] = core.Aws.ACCOUNT_ID
        env_vars['INSTANCE_TYPES'] = self.config["imageBuilder"]["instanceTypes"][0]
        env_vars['INSTANCE_PROFILE'] = self.imagebuilder_instance_profile_name
        env_vars['SUBNET_ID'] = self.imagebuilder_subnet_id
        env_vars['RESOURCE_TAGS'] = json.dumps(self.config["imageBuilder"]["extraTags"], separators=(',', ':'))
        env_vars['SECURITY_GROUP_ID'] = self.imagebuilder_security_group
        env_vars['SNS_TOPIC_ARN'] = self.imagebuilder_topic_arn

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcPatchCreateImagePipelineLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.ami_patch.create_image_pipeline.lambda_handler",
            role=lambda_role,
            environment=env_vars,
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_patch_start_image_pipeline_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcPatchStartImagePipelineLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcPatchStartImagePipelineLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.ami_patch.start_image_pipeline.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_patch_poll_ami_status_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcPatchPollAmiStatusLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcPatchPollAmiStatusLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.ami_patch.poll_ami_status.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_patch_ami_details_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcPatchAmiDetailsLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcPatchAmiDetailsLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.ami_patch.get_ami_details.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_patch_delete_dynamic_imagebuilder_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcPatchDeleteDynamicLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)
        lambda_role.add_to_policy(self.get_delete_imagebuilder_pipeline_policy())
        lambda_role.add_to_policy(self.get_image_builder_delete_iam_role_policy())

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcPatchDeleteDynamicLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.ami_patch.delete_dynamic_imagebuilder.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_ami_patch_notify_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcPatchNotifyLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcPatchNotifyLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.ami_patch.notify.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda


    ##########################################################
    # </END> Define PATCH AMI Lifecycle lambdas
    ##########################################################


    ##########################################################
    # <START> Define MARK FOR PRODUCTION AMI Lifecycle lambdas
    ##########################################################

    def get_mark_for_production_entry_point_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcMarkForProductionEntryPointLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcMarkForProductionEntryPointLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.mark_for_production.entry_point.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_mark_for_production_backup_lambda(self, bucket_name: str) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcMarkForProductionBackupLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)
        lambda_role.add_to_policy(self.get_ami_backup_policy())
        
        env_vars = self.get_common_lifecycle_envvars()
        env_vars['BUCKET'] = bucket_name

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcMarkForProductionBackupLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.mark_for_production.ami_backup.lambda_handler",
            role=lambda_role,
            environment=env_vars,
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_mark_for_production_backup_status_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcMarkForProductionBackupStatusLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)
        lambda_role.add_to_policy(self.get_ami_backup_status_policy())

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcMarkForProductionBackupStatusLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.mark_for_production.ami_backup_status.lambda_handler",
            role=lambda_role,
            environment=self.get_common_lifecycle_envvars(),
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    def get_mark_for_production_notify_lambda(self) -> aws_lambda.Function:
        # IAM Role for Lambda
        lambda_role = self.get_lambda_execution_role(f"AmiLcMarkForProductionNotifyLambdaRole")
        self.set_common_lifecycle_roles(lambda_role)

        env_vars = self.get_common_lifecycle_envvars()
        env_vars['EVENT_RECEIVER_QUEUE_URL'] = self.ami_creation_receiver_queue.queue_url
        env_vars['PATCH_EVENT_RECEIVER_QUEUE_URL'] = self.ami_patch_receiver_queue.queue_url

        _lambda = aws_lambda.Function(
            scope=self,
            id=f"AmiLcMarkForProductionNotifyLambda",
            code=aws_lambda.Code.from_asset(f"{os.path.dirname(__file__)}/resources/lambda/ami_lifecycle"),
            handler="app.mark_for_production.notify.lambda_handler",
            role=lambda_role,
            environment=env_vars,
            layers=[self.ami_lifecycle_deps_layer],
            timeout=core.Duration.minutes(3),
            runtime=aws_lambda.Runtime.PYTHON_3_9
        )

        return _lambda

    ##########################################################
    # </END> Define MARK FOR PRODUCTION AMI Lifecycle lambdas
    ##########################################################


    ##########################################################
    ##########################################################
    # </END> AMI Lifecycle Lambdas and Roles
    ##########################################################
    ##########################################################
