import fnmatch
import json
import os
import pytest
import re
import typing
from cdk_expects_matcher.CdkMatchers import have_resource, ANY_VALUE
from expects import expect
from unittest import TestCase
from utils.CdkUtils import CdkUtils

cdk_out_dir = 'cdk.out'
suffix = 'template.json'


def find(pattern, path) -> list:
    result = []
    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                result.append(os.path.join(root, name))
    return result


def read(file_path) -> dict:
    with open(file_path, 'r') as file:
        cfn_template = json.loads(file.read())
        file.close()

    return cfn_template


@pytest.fixture(scope="session")
def synth(request) -> None:
    os.system('rm -rf ./cdk.out/')
    os.system('cdk synth --json')


class RootTestCase(TestCase):
    cfn_template = {}  # This is to be injected by a fixture

    secret = 'AWS::SecretsManager::Secret'
    secret_rotation_schedule = 'AWS::SecretsManager::RotationSchedule'
    secret_resource_policy = 'AWS::SecretsManager::ResourcePolicy'
    kms_alias = 'AWS::KMS::Alias'
    kms_key = 'AWS::KMS::Key'
    lambda_ = 'AWS::Lambda::Function'
    lambda_layer = 'AWS::Lambda::LayerVersion'
    lambda_permission = 'AWS::Lambda::Permission'
    asg = 'AWS::AutoScaling::AutoScalingGroup'
    asg_lc = 'AWS::AutoScaling::LaunchConfiguration'
    eks_cluster = 'Custom::AWSCDK-EKS-Cluster'
    eks_node_group = 'AWS::EKS::Nodegroup'
    eks_openid_connect_provider = 'Custom::AWSCDKOpenIdConnectProvider'
    iam_role = 'AWS::IAM::Role'
    iam_user = 'AWS::IAM::User'
    iam_group = 'AWS::IAM::Group'
    iam_managed_policy = 'AWS::IAM::ManagedPolicy'
    iam_instance_profile = 'AWS::IAM::InstanceProfile'
    eks_k8s_manifest = 'Custom::AWSCDK-EKS-KubernetesResource'
    eks_k8s_patch = 'Custom::AWSCDK-EKS-KubernetesPatch'
    ecr_repository = 'AWS::ECR::Repository'
    ecr_replication_configuration = 'AWS::ECR::ReplicationConfiguration'
    security_hub = 'AWS::SecurityHub::Hub"'
    s3_bucket = 'AWS::S3::Bucket'
    s3_bucket_policy = 'AWS::S3::BucketPolicy'
    vpc = 'AWS::EC2::VPC'
    vpc_endpoint = 'AWS::EC2::VPCEndpoint'
    vpc_cidr_block = 'AWS::EC2::VPCCidrBlock'
    code_commit_repo = 'AWS::CodeCommit::Repository'
    code_pipeline = 'AWS::CodePipeline::Pipeline'
    hosted_zone = 'AWS::Route53::HostedZone'
    acm_certificate = 'AWS::CertificateManager::Certificate'
    helm_chart = 'Custom::AWSCDK-EKS-HelmChart'
    eks_query_object_value = 'Custom::AWSCDK-EKS-KubernetesObjectValue'
    route53_record_set = 'AWS::Route53::RecordSet'
    imagebuilder_component = 'AWS::ImageBuilder::Component'
    imagebuilder_recipe = 'AWS::ImageBuilder::ImageRecipe'
    imagebuilder_infrastructure_configuration = 'AWS::ImageBuilder::InfrastructureConfiguration'
    imagebuilder_image_pipeline = 'AWS::ImageBuilder::ImagePipeline'
    imagebuilder_distribution_config = 'AWS::ImageBuilder::DistributionConfiguration'
    sns_topic = 'AWS::SNS::Topic'
    sqs_queue = 'AWS::SQS::Queue'
    sns_subscription = 'AWS::SNS::Subscription'
    ec2_security_group = 'AWS::EC2::SecurityGroup'
    ec2_vpc = 'AWS::EC2::VPC'
    ecs_cluster = 'AWS::ECS::Cluster'
    ec_subnet_group = 'AWS::ElastiCache::SubnetGroup'
    ec_replication_group = 'AWS::ElastiCache::ReplicationGroup'
    backup_plan = 'AWS::Backup::BackupPlan'
    backup_vault = 'AWS::Backup::BackupVault'
    backup_selection = 'AWS::Backup::BackupSelection'
    cw_metric = 'AWS::Logs::MetricFilter'
    cw_alarm = 'AWS::CloudWatch::Alarm'
    cw_events_rule = 'AWS::Events::Rule'
    cw_log_group = 'AWS::Logs::LogGroup'
    custom_log_retention = 'Custom::LogRetention'
    ssm_maintenance_window = 'AWS::SSM::MaintenanceWindow'
    ssm_maintenance_window_target = 'AWS::SSM::MaintenanceWindowTarget'
    ssm_maintenance_window_task = 'AWS::SSM::MaintenanceWindowTask'
    custom_resource = 'Custom::AWS'
    iam_policy = 'AWS::IAM::Policy'
    state_machine = 'AWS::StepFunctions::StateMachine'
    wafv2_webACL = "AWS::WAFv2::WebACL"
    wafv2_webACL_regexPatternSet = 'AWS::WAFv2::RegexPatternSet'
    wafv2_webACL_associate_ALB = "AWS::WAFv2::WebACLAssociation"
    cw_dashboard = "AWS::CloudWatch::Dashboard"
    cw_alarm = 'AWS::CloudWatch::Alarm'
    cw_compositeAlarm = 'AWS::CloudWatch::CompositeAlarm'
    ecs_fargate_service = "AWS::ECS::Service"
    asg_scaling_policy = "AWS::ApplicationAutoScaling::ScalingPolicy"
    ssm_maintenance_window = 'AWS::SSM::MaintenanceWindow'
    ssm_maintenance_window_target = 'AWS::SSM::MaintenanceWindowTarget'
    ssm_maintenance_window_task = 'AWS::SSM::MaintenanceWindowTask'
    custom_resource = 'Custom::AWS'
    custom_log_retention = 'Custom::LogRetention'
    event_rule = 'AWS::Events::Rule'
    custom_cfn_resource = 'AWS::CloudFormation::CustomResource'
    event_bus_policy = 'AWS::Events::EventBusPolicy'
    dynamodb_table = 'AWS::DynamoDB::Table'

    __test__ = False

    def test_s3_bucket_encryption(self):
        assert self.get_template_str().count(f'"{self.s3_bucket}"') == \
               self.get_template_str().count('"ServerSideEncryptionConfiguration"') == \
               self.get_template_str().count('"BucketEncryption"')

    def test_s3_block_public_access(self):
        assert self.get_template_str().count(f'"{self.s3_bucket}"') == \
               self.get_template_str().count('"PublicAccessBlockConfiguration"') == \
               self.get_template_str().count('"BlockPublicAcls":true') == \
               self.get_template_str().count('"BlockPublicPolicy":true') == \
               self.get_template_str().count('"IgnorePublicAcls":true') == \
               self.get_template_str().count('"RestrictPublicBuckets":true')

    def test_kms_key_rotation_enabled(self):
        assert self.get_template_str().count(f'"{self.kms_key}"') == \
               self.get_template_str().count('"EnableKeyRotation":true')

    def test_s3_bucket_baseline(self):
        if self.get_template_str().count(f'"{self.s3_bucket}"'):
            expect(self.cfn_template).to(have_resource(self.s3_bucket, {
                "BucketEncryption": {
                    "ServerSideEncryptionConfiguration": [
                        {
                            "ServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "aws:kms"
                            }
                        }
                    ]
                },
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": 'true',
                    "BlockPublicPolicy": 'true',
                    "IgnorePublicAcls": 'true',
                    "RestrictPublicBuckets": 'true'
                },
            }))

    def test_s3_bucket_enforce_encryption_policy_applied(self):

        assert self.get_template_str().count(f'"{self.s3_bucket_policy}"') == \
               self.get_template_str().count(f'"{self.s3_bucket}"')

        if self.get_template_str().count(f'"{self.s3_bucket_policy}"'):
            expect(self.cfn_template).to(have_resource(self.s3_bucket_policy, {
                "Bucket": {
                    "Ref": ANY_VALUE
                },
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Action": "s3:*",
                            "Condition": {
                                "Bool": {
                                    "aws:SecureTransport": "false"
                                }
                            },
                            "Effect": "Deny",
                            "Principal": "*",
                            "Resource": [
                                {
                                    "Fn::GetAtt": [
                                        ANY_VALUE,
                                        "Arn"
                                    ]
                                },
                                {
                                    "Fn::Join": [
                                        "",
                                        [
                                            {
                                                "Fn::GetAtt": [
                                                    ANY_VALUE,
                                                    "Arn"
                                                ]
                                            },
                                            "/*"
                                        ]
                                    ]
                                }
                            ]
                        }
                    ],
                    "Version": "2012-10-17"
                }
            }))

    def test_no_iam_users_created(self) -> None:
        assert self.iam_user not in self.get_template_str()

    def test_no_iam_groups_created(self) -> None:
        assert self.iam_group not in self.get_template_str()

    def exists(self, value) -> bool:
        exists = False
        exists = value.replace("\"", "\\\"") in self.get_template_str() or exists
        return exists

    def regex_search(self, value: typing.Pattern[typing.AnyStr]) -> bool:
        exists = False
        exists = re.search(value, self.get_template_str()) or exists
        return exists

    def get_template_str(self) -> dict:
        return json.dumps(self.cfn_template).replace(' ', '')

    @staticmethod
    def load_stack_template(stack_name: str) -> dict:
        return read(f'{cdk_out_dir}/{stack_name}.{suffix}')
