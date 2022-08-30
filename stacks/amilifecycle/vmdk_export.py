#!/usr/bin/env python

"""
    vmdk_export.py:
    AMI Lifecycle CDK stack which creates the AWS infrastrcuture required
    to use the VM Import/Export service to export an AMI Lifecycle generated 
    AMI to VMDK format and save the VMDK file to an S3 bucket.
"""

from aws_cdk import aws_iam as iam
from aws_cdk import aws_s3 as s3
from aws_cdk import core
from utils.CdkConstants import CdkConstants


class VmdkExportStack(core.Stack):
    """
        AMI Lifecycle CDK stack which creates the AWS infrastrcuture required
        to use the VM Import/Export service to export an AMI Lifecycle generated 
        AMI to VMDK format and save the VMDK file to an S3 bucket.
    """

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        ROLE_NAME = "vmimport"

        # create S3 bucket to be used for VMDK export
        vmdk_export_bucket = s3.Bucket(
            self, 
            "vmdk-export-bucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            removal_policy=core.RemovalPolicy.DESTROY,
            public_read_access=False,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True
        )

        # Role to be assumed for the VMDK export
        # This role requires a specific name; vmimport
        vmimport_role = iam.Role(
            self, 
            'vm-import-role',
            assumed_by=iam.ServicePrincipal("vmie.amazonaws.com"),
            role_name=ROLE_NAME
        )

        vmimport_role.add_to_policy(iam.PolicyStatement(
            actions=[
                "ec2:CopySnapshot",
                "ec2:Describe*",
                "ec2:ModifySnapshotAttribute",
                "ec2:RegisterImage",
                "ec2:CreateTags",
                "ec2:ExportImage"
            ],
            resources=["*"]
        ))

        vmimport_role.add_to_policy(iam.PolicyStatement(
                resources=[
                    vmdk_export_bucket.bucket_arn,
                    f"{vmdk_export_bucket.bucket_arn}/*"
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
        )

        # vmimport role requires a stringequals condition filter on the AssumeRolePolicyDocument
        vmimport_role_ref = vmimport_role.node.default_child
        vmimport_role_ref.add_override(
            "Properties.AssumeRolePolicyDocument.Statement.0.Condition.StringEquals.sts:Externalid",
            [ROLE_NAME]
        )

        # outputs to be consumed by other stacks
        core.CfnOutput(
            self,
            "vmdk-exportbucket-arn-output",
            value=vmdk_export_bucket.bucket_arn,
            description="ARN of the S3 Bucket used for VMDK export",
        ).override_logical_id(CdkConstants.VMDK_EXPORT_BUCKET_ARN)

        ##################################################
        ## <START> Export values for consumption
        ## by other stacks
        ##################################################

        self.bucket_arn = vmdk_export_bucket.bucket_arn

        ##################################################
        ## </END> Export values for consumption
        ## by other stacks
        ##################################################
