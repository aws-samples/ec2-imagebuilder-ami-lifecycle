#!/usr/bin/env python

"""
    ami_lifecycle_tagger.py:
    AMI Lifecycle CDK stack which creates a role that can be assumed by
    the AMI Lifecycle Orchestrator API to write AMI Lifecycle metadata to
    AMI tags.
"""

from aws_cdk import aws_iam as iam
from aws_cdk import core
from utils.CdkConstants import CdkConstants
from utils.CdkUtils import CdkUtils


class AmiLifecycleTaggerStack(core.Stack):
    """
        AMI Lifecycle CDK stack which creates a role that can be assumed by
        the AMI Lifecycle Orchestrator API to write AMI Lifecycle metadata to
        AMI tags.
    """

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        config = CdkUtils.get_project_settings()['amiLifecycle']

        ##########################################################
        # <START> Create Role that permits AMI tagging from
        #         the AMI Orchestrator API
        ##########################################################

        # Create a role for cross account access to AMI tags
        ami_tags_crossaccount_role = iam.Role(
            scope=self,
            id="ami-lifecycle-tagger-role",
            assumed_by=iam.ArnPrincipal(f"arn:aws:iam::{core.Aws.ACCOUNT_ID}:root"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ],
            role_name=f"{config['amiTagger']['taggerRole']}"
        )

        ami_tags_crossaccount_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=[
                    f"*"],
                actions=[
                    "ec2:DescribeTags",
                    "ec2:DescribeImageAttribute",
                    "ec2:DescribeImages",
                    "ec2:DeleteTags",
                    "ec2:CreateTags",
                    "ec2:RegisterImage",
                    "ec2:ModifyImageAttribute"
                ]
            )
        )

        # outputs to be consumed by other stacks
        core.CfnOutput(
            self,
            "ami-lifecycle-tagger-role-output",
            value=ami_tags_crossaccount_role.role_arn,
            description="ARN of the cross account AMI Tagger role",
        ).override_logical_id(CdkConstants.CROSS_ACCOUNT_TAGGER_ROLE_ARN)
