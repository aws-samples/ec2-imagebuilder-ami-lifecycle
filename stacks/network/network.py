#!/usr/bin/env python

"""
    network.py:
    AMI Lifecycle CDK stack which creates the AWS network infrastructure
    such as VPC, public/private subnet as required by the AMI lifecycle solution.
"""

from aws_cdk import aws_ec2 as ec2
from aws_cdk import core
from utils.CdkConstants import CdkConstants
from utils.CdkUtils import CdkUtils


class NetworkStack(core.Stack):
    """
        AMI Lifecycle CDK stack which creates the AWS network infrastructure
        such as VPC, public/private subnet as required by the AMI lifecycle solution.
    """

    def __init__(self, scope: core.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        config = CdkUtils.get_project_settings()

        ##################################################
        ## <START> Network prequisites
        ##################################################

        # create the secure proxy VPC
        vpc = ec2.Vpc(
            self,
            "ami-lifecycle-vpc",
            cidr=config["vpc"]["cidr"],
            max_azs=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="ami-lifecycle-subnet-public",
                    cidr_mask=config["vpc"]["subnets"]["mask"],
                    subnet_type=ec2.SubnetType.PUBLIC
                ),
                ec2.SubnetConfiguration(
                    name="ami-lifecycle-subnet-private",
                    cidr_mask=config["vpc"]["subnets"]["mask"],
                    subnet_type=ec2.SubnetType.PRIVATE
                )
            ]
        )

        ##################################################
        ## </END> Network prequisites
        ##################################################


        ##################################################
        ## <START> CDK Outputs
        ##################################################

        core.CfnOutput(
            self, 
            id="vpc-id", 
            value=vpc.vpc_id,
            description="VPC Id"
        ).override_logical_id(CdkConstants.VPC_ID)

        core.CfnOutput(
            self, 
            id="vpc-public-subnet-id-output", 
            value=vpc.public_subnets[0].subnet_id,
            description="VPC Public Subnet Id"
        ).override_logical_id(CdkConstants.VPC_PUBLIC_SUBNET_ID)

        core.CfnOutput(
            self, 
            id="vpc-private-subnet-id-output", 
            value=vpc.private_subnets[0].subnet_id,
            description="VPC Private Subnet Id"
        ).override_logical_id(CdkConstants.VPC_PRIVATE_SUBNET_ID)

        ##################################################
        ## </END> CDK Outputs
        ##################################################


        ##################################################
        ## <START> Export values for consumption
        ## by other stacks
        ##################################################

        self.vpc = vpc
        self.vpc_private_subnet_id = vpc.private_subnets[0].subnet_id

        ##################################################
        ## </END> Export values for consumption
        ## by other stacks
        ##################################################
