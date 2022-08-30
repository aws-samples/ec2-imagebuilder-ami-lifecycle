from enum import Enum

from aws_cdk import (
    core,
    aws_iam as iam
)

class IAMPrincipals(Enum):
    LAMBDA: iam.IPrincipal = iam.ServicePrincipal(service=f'lambda.{core.Aws.URL_SUFFIX}')
    EC2: iam.IPrincipal = iam.ServicePrincipal(service=f'ec2.{core.Aws.URL_SUFFIX}')
    SSM: iam.IPrincipal = iam.ServicePrincipal(service=f'ssm.{core.Aws.URL_SUFFIX}')
    EKS: iam.IPrincipal = iam.ServicePrincipal(service=f'eks.{core.Aws.URL_SUFFIX}')
    S3: iam.IPrincipal = iam.ServicePrincipal(service=f's3.{core.Aws.URL_SUFFIX}')
    SECRETS_MANAGER: iam.IPrincipal = iam.ServicePrincipal(service=f'secretsmanager.{core.Aws.URL_SUFFIX}')
    CODE_BUILD: iam.IPrincipal = iam.ServicePrincipal(service=f'codebuild.{core.Aws.URL_SUFFIX}')
    CODE_PIPELINE: iam.IPrincipal = iam.ServicePrincipal(service=f'codepipeline.{core.Aws.URL_SUFFIX}')
    CLOUD_FORMATION: iam.IPrincipal = iam.ServicePrincipal(service=f'cloudformation.{core.Aws.URL_SUFFIX}')
    ROUTE_53: iam.IPrincipal = iam.ServicePrincipal(service=f'route53.{core.Aws.URL_SUFFIX}')
    LOGS: iam.IPrincipal = iam.ServicePrincipal(service=f'logs.{core.Aws.URL_SUFFIX}')
    BACKUP: iam.IPrincipal = iam.ServicePrincipal(service=f'backup.{core.Aws.URL_SUFFIX}')
    IMAGE_BUILDER: iam.IPrincipal = iam.ServicePrincipal(service=f'imagebuilder.{core.Aws.URL_SUFFIX}')
    SNS: iam.IPrincipal = iam.ServicePrincipal(service=f'sns.{core.Aws.URL_SUFFIX}')
    SQS: iam.IPrincipal = iam.ServicePrincipal(service=f'sqs.{core.Aws.URL_SUFFIX}')
    DELIVERY_LOGS: iam.IPrincipal = iam.ServicePrincipal(service=f'delivery.logs.{core.Aws.URL_SUFFIX}')
    CLOUDWATCH: iam.IPrincipal = iam.ServicePrincipal(service=f'cloudwatch.{core.Aws.URL_SUFFIX}')
    DYNAMODB: iam.IPrincipal = iam.ServicePrincipal(service=f'dynamodb.{core.Aws.URL_SUFFIX}')
    VPC_FLOW_LOGS: iam.IPrincipal = iam.ServicePrincipal(service=f'vpc-flow-logs.{core.Aws.URL_SUFFIX}')
    CLOUDTRAIL: iam.IPrincipal = iam.ServicePrincipal(service=f'cloudtrail.{core.Aws.URL_SUFFIX}')
    API_GATEWAY: iam.IPrincipal = iam.ServicePrincipal(service=f'apigateway.{core.Aws.URL_SUFFIX}')
    STEP_FUNCTIONS: iam.IPrincipal = iam.ServicePrincipal(service=f'states.{core.Aws.URL_SUFFIX}')
    ALBV2: iam.IPrincipal
    VM_IMPORT: iam.IPrincipal = iam.PrincipalWithConditions(
        principal=iam.ServicePrincipal(f'vmie.{core.Aws.URL_SUFFIX}').grant_principal,
        conditions={
            "StringEquals": {
                "sts:ExternalId": "vmimport"
            }
        }
    )