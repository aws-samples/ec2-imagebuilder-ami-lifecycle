#!/usr/bin/env python

"""
    image_builder.py:
    AMI Lifecycle CDK stack which creates the AWS infrastrcuture required
    by the AMI Lifecycle solution in order to leverage the EC2 Image Builder
    service to generate AMIs from custom component definitions.
"""

import os

from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_imagebuilder as imagebuilder
from aws_cdk import aws_kms as kms
from aws_cdk import aws_s3_assets as assets
from aws_cdk import aws_sns as sns
from aws_cdk import core
from utils.CdkConstants import CdkConstants
from utils.CdkUtils import CdkUtils


class ImageBuilderStack(core.Stack):
    """
        AMI Lifecycle CDK stack which creates the AWS infrastrcuture required
        by the AMI Lifecycle solution in order to leverage the EC2 Image Builder
        service to generate AMIs from custom component definitions.
    """

    def __init__(
            self, 
            scope: core.Construct, 
            construct_id: str,
            vpc: ec2.Vpc,
            vpc_private_subnet_id: str,
            **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        config = CdkUtils.get_project_settings()

        ##################################################
        ## <START> EC2 ImageBuilder generic resources
        ##################################################

        # create a KMS key to encrypt project contents
        kms_key = kms.Key(
            self, 
            "image-builder-kms-key",
            admins=[iam.AccountPrincipal(account_id=core.Aws.ACCOUNT_ID)],
            enable_key_rotation=True,
            enabled=True,
            description="KMS key used with EC2 Imagebuilder Ami Lifecycle project",
            removal_policy=core.RemovalPolicy.DESTROY,
            alias="image-builder-kms-key-alias"
        )

        kms_key.grant_encrypt_decrypt(iam.ServicePrincipal(service=f'imagebuilder.{core.Aws.URL_SUFFIX}'))

        # below role is assumed by the ImageBuilder ec2 instance
        image_builder_image_role = iam.Role(self, "image-builderimage-role", assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"))
        image_builder_image_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))
        image_builder_image_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("EC2InstanceProfileForImageBuilder"))
        kms_key.grant_encrypt_decrypt(image_builder_image_role)
        kms_key.grant(image_builder_image_role, "kms:Describe*")
        image_builder_image_role.add_to_policy(iam.PolicyStatement(
            actions=[
                "logs:CreateLogStream",
                "logs:CreateLogGroup",
                "logs:PutLogEvents"
            ],
            resources=[
                core.Arn.format(components=core.ArnComponents(
                    service="logs",
                    resource="log-group",
                    resource_name="aws/imagebuilder/*"
                ), stack=self)
            ],
        ))

        # create an instance profile to attach the role
        instance_profile = iam.CfnInstanceProfile(
            self, "imagebuilder-instance-profile",
            instance_profile_name="ami-lifecycle-imagebuilder-instance-profile",
            roles=[image_builder_image_role.role_name]
        )

        sns_topic = sns.Topic(
            self, "imagebuilder-topic",
            topic_name="ami-lifecycle-imagebuilder-topic",
            master_key=kms_key
        )

        sns.Subscription(
            self, "imagebuilder-subscription",
            topic=sns_topic,
            endpoint=config["imageBuilder"]["imageBuilderEmailAddress"],
            protocol=sns.SubscriptionProtocol.EMAIL
        )

        sns_topic.grant_publish(image_builder_image_role)
        kms_key.grant_encrypt_decrypt(iam.ServicePrincipal(service=f'sns.{core.Aws.URL_SUFFIX}'))

        # SG for the image build
        imagebuilder_sg = ec2.SecurityGroup(
            self, "imagebuilder-sg",
            vpc=vpc,
            allow_all_outbound=True,
            description="Security group for the EC2 Image Builder Pipeline: " + self.stack_name + "-Pipeline",
            security_group_name="ami-lifecycle-imagebuilder-sg"
        )

        # create infrastructure configuration to supply instance type
        infra_config = imagebuilder.CfnInfrastructureConfiguration(
            self, "infra-config",
            name="ami-lifecycle-infra-config",
            instance_types=config["imageBuilder"]["instanceTypes"],
            instance_profile_name=instance_profile.instance_profile_name,
            subnet_id=vpc_private_subnet_id,
            security_group_ids=[imagebuilder_sg.security_group_id],
            resource_tags={
                "project": "ec2-imagebuilder-ami-lifecycle"
            },
            terminate_instance_on_failure=True,
            sns_topic_arn=sns_topic.topic_arn
        )
        # infrastructure need to wait for instance profile to complete before beginning deployment.
        infra_config.add_depends_on(instance_profile)

        ##################################################
        ## </END> EC2 ImageBuilder generic resources
        ##################################################


        ##################################################
        ## <START> ImageBuilder
        ##################################################

        kms_key.grant_encrypt_decrypt(iam.ServicePrincipal(service=f'logs.{core.Aws.URL_SUFFIX}'))

        generic_asset = assets.Asset(self, "GenericAsset",
                path=os.path.abspath("stacks/imagebuilder/components/install_generic_component.yml"))

        # create component to install secure proxy
        generic_component = imagebuilder.CfnComponent(
            self, "generic-component",
            name=self.stack_name + "-generic-component",
            platform="Linux",
            version=config["imageBuilder"]["component_version"],
            uri=generic_asset.s3_object_url,
            kms_key_id=kms_key.key_arn,
            tags={
                "imagePipeline": "AMILifecycleImageBuilder",
                "project": "ec2-imagebuilder-ami-lifecycle"
            }
        )

         # recipe that installs the secure proxy components together with a Amazon Linux 2 base image
        image_recipe = imagebuilder.CfnImageRecipe(
            self, "image-recipe",
            name="ami-lifecycle-image-recipe",
            version=config["imageBuilder"]["recipe_version"],
            components=[
                {
                    "componentArn": generic_component.attr_arn
                },
                {
                    "componentArn": core.Arn.format(components=core.ArnComponents(
                        service="imagebuilder",
                        resource="component",
                        resource_name="amazon-cloudwatch-agent-linux/x.x.x",
                        account="aws"
                    ), stack=self)
                },
                {
                    "componentArn": core.Arn.format(components=core.ArnComponents(
                        service="imagebuilder",
                        resource="component",
                        resource_name="aws-cli-version-2-linux/x.x.x",
                        account="aws"
                    ), stack=self)
                }
            ],
            parent_image=f"arn:aws:imagebuilder:{self.region}:aws:image/{config['imageBuilder']['baseImageArn']}",
            block_device_mappings=[
                imagebuilder.CfnImageRecipe.InstanceBlockDeviceMappingProperty(
                    device_name="/dev/xvda",
                    ebs=imagebuilder.CfnImageRecipe.EbsInstanceBlockDeviceSpecificationProperty(
                        delete_on_termination=True,
                        # Encryption is disabled, because the export VM doesn't support encrypted ebs
                        encrypted=False,
                        volume_size=config["imageBuilder"]["ebsVolumeSize"],
                        volume_type="gp2"
                    )
                )],
            description="Recipe to build and validate GenricComponentImageRecipe",
            tags={
                "project": "ec2-imagebuilder-ami-lifecycle"
            },
            working_directory="/imagebuilder"
        )      

        # Distribution configuration for AMIs
        distribution_config = imagebuilder.CfnDistributionConfiguration(
            self, 'distribution-config',
            name='ami-lifecycle-distribution-config',
            distributions=[
                imagebuilder.CfnDistributionConfiguration.DistributionProperty(
                    region=self.region,
                    ami_distribution_configuration={
                        'Name': core.Fn.sub(f'AmiLifecycle-ImageRecipe-{{{{ imagebuilder:buildDate }}}}'),
                        'AmiTags': {
                            "project": "ec2-imagebuilder-ami-lifecycle",
                            'Pipeline': "AmiLifecyclePipeline"
                        }
                    }
                )
            ]
        )

        # build the imagebuilder pipeline
        pipeline = imagebuilder.CfnImagePipeline(
            self, "pipeline",
            name="ami-lifecycle-pipeline",
            image_recipe_arn=image_recipe.attr_arn,
            infrastructure_configuration_arn=infra_config.attr_arn,
            tags={
                "project": "ec2-imagebuilder-ami-lifecycle"
            },
            description="Image Pipeline for: AmiLifecyclePipeline",
            enhanced_image_metadata_enabled=True,
            image_tests_configuration=imagebuilder.CfnImagePipeline.ImageTestsConfigurationProperty(
                image_tests_enabled=True,
                timeout_minutes=90
            ),
            distribution_configuration_arn=distribution_config.attr_arn,
            status="ENABLED"
        )
        pipeline.add_depends_on(infra_config)

        ##################################################
        ## </END> ImageBuilder
        ##################################################


        ##################################################
        ## <START> CDK Outputs
        ##################################################

        core.CfnOutput(
            self, 
            id="pipeline-arn-output", 
            value=pipeline.attr_arn,
            description="Ami Lifecycle EC2 ImageBuilder Pipeline Arn"
        ).override_logical_id(CdkConstants.IMAGEBUILDER_PIPELINE_ARN)

        core.CfnOutput(
            self, 
            id="ec2-instance-profile-arn-output", 
            value=instance_profile.attr_arn,
            description="Ami Lifecycle EC2 Instance Profile ARN"
        ).override_logical_id(CdkConstants.EC2_INSTANCE_PROFILE_ARN)

        core.CfnOutput(
            self, 
            id="ec2-instance-profile-name-output", 
            value=instance_profile.instance_profile_name,
            description="Ami Lifecycle EC2 Instance Profile Name"
        ).override_logical_id(CdkConstants.EC2_INSTANCE_PROFILE_NAME)

        core.CfnOutput(
            self, 
            id="image-builder-topic-arn-output", 
            value=sns_topic.topic_arn,
            description="Ami Lifecycle Image Builder Topic ARN"
        ).override_logical_id(CdkConstants.IMAGEBUILDER_TOPIC_ARN)

        core.CfnOutput(
            self, 
            id="image-builder-security-group-id-output", 
            value=imagebuilder_sg.security_group_id,
            description="Ami Lifecycle Image Builder Security Group Id"
        ).override_logical_id(CdkConstants.IMAGEBUILDER_SECURITY_GROUP_ID)

        core.CfnOutput(
            self, 
            id="image-builder-kms-key-arn-output", 
            value=kms_key.key_arn,
            description="Ami Lifecycle Image Builder Kms Key Arn"
        ).override_logical_id(CdkConstants.IMAGEBUILDER_KMS_KEY_ARN)

        ##################################################
        ## </END> CDK Outputs
        ##################################################

        ##################################################
        ## <START> Export values for consumption
        ## by other stacks
        ##################################################

        self.image_builder_pipeline_arn = pipeline.attr_arn
        self.image_builder_instance_profile_arn = instance_profile.attr_arn
        self.image_builder_instance_profile_name = instance_profile.instance_profile_name
        self.image_builder_sns_topic_arn = sns_topic.topic_arn
        self.image_builder_security_group_id = imagebuilder_sg.security_group_id
        self.image_builder_kms_key_arn = kms_key.key_arn

        ##################################################
        ## </END> Export values for consumption
        ## by other stacks
        ##################################################
