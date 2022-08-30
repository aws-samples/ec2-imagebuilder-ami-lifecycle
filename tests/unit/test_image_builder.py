import json

import pytest
from expects import expect

from aws_cdk import (
    core
)

from cdk_expects_matcher.CdkMatchers import have_resource, ANY_VALUE, contain_metadata_path
import tests.utils.base_test_case as tc
from utils.CdkUtils import CdkUtils


@pytest.fixture(scope="class")
def image_builder_stack(request):
    request.cls.cfn_template = tc.BaseTestCase.load_stack_template(f"AmiLifecycleImageBuilder")


@pytest.mark.usefixtures('synth', 'image_builder_stack')
class TestImageBuilderStack(tc.BaseTestCase):
    """
        Test case for ImageBuilderStack
    """

    config = CdkUtils.get_project_settings()

    ##################################################
    ## <START> EC2 Security Group tests
    ##################################################
    def test_no_admin_permissions(self):
        assert json.dumps(self.cfn_template).count(':iam::aws:policy/AdministratorAccess') == 0

    def test_imagebuilder_instance_profile_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.iam_instance_profile, "imagebuilder-instance-profile"
            )
        )

    def test_security_group_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.ec2_security_group, "imagebuilder-sg")
        )

    def test_image_role_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.iam_role, "image-builderimage-role")
        )

    def test_image_role_policy(self):
        expect(self.cfn_template).to(have_resource(
            self.iam_role,
            {
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Action": "sts:AssumeRole",
                            "Effect": "Allow",
                            "Principal": {
                                "Service": "ec2.amazonaws.com"
                            }
                        }
                    ],
                    "Version": "2012-10-17"
                },
                "ManagedPolicyArns": [
                    {
                        "Fn::Join": [
                            "",
                            [
                                "arn:",
                                {
                                    "Ref": "AWS::Partition"
                                },
                                ":iam::aws:policy/AmazonSSMManagedInstanceCore"
                            ]
                        ]
                    },
                    {
                        "Fn::Join": [
                            "",
                            [
                                "arn:",
                                {
                                    "Ref": "AWS::Partition"
                                },
                                ":iam::aws:policy/EC2InstanceProfileForImageBuilder"
                            ]
                        ]
                    }
                ]
            }
        ))
    ##################################################
    ## </END> EC2 Security Group tests
    ##################################################

    ##################################################
    ## <START> KMS tests
    ##################################################
    def test_kms_key_rotation_created(self):
        expect(self.cfn_template).to(have_resource(self.kms_key, {
            "EnableKeyRotation": True
        }))

    def test_kms_key_alias_created(self):
        expect(self.cfn_template).to(have_resource(self.kms_alias, {
            "AliasName": "alias/image-builder-kms-key-alias"
        }))

    def test_kms_key_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.kms_key, "image-builder-kms-key"
            )
        )
    ##################################################
    ## </END> AWS KMS tests
    ##################################################


    ##################################################
    ## <START> EC2 Imagebuilder tests
    ##################################################
    def test_infra_config_created(self):
        expect(self.cfn_template).to(contain_metadata_path(
            self.imagebuilder_infrastructure_configuration, "infra-config"
            )
        )

    def test_generic_component_created(self):
        expect(self.cfn_template).to(contain_metadata_path(
                self.imagebuilder_component, 'generic-component'
            )
        )
    
    def test_recipe_created(self):
        expect(self.cfn_template).to(contain_metadata_path(
            self.imagebuilder_recipe, "image-recipe"
            )
        )

    def test_pipeline_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.imagebuilder_image_pipeline, "pipeline"
            )
        )

    def test_distribution_config(self):
        expect(self.cfn_template).to(
            have_resource(self.imagebuilder_distribution_config, {
                "Distributions": [
                    {
                        "AmiDistributionConfiguration": {
                            "Name": {
                                "Fn::Sub": f'AmiLifecycle-ImageRecipe-{{{{ imagebuilder:buildDate }}}}'
                            },
                            "AmiTags": {
                                "project": "ec2-imagebuilder-ami-lifecycle",
                            "Pipeline": "AmiLifecyclePipeline"
                            }
                        },
                        "Region": core.Aws.REGION
                    }
                ],
                "Name": 'ami-lifecycle-distribution-config'
            }))

    def test_sns_topic_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.sns_topic, "imagebuilder-topic"))

    def test_sns_subscription_created(self):
        expect(self.cfn_template).to(
            have_resource(self.sns_subscription,
                          {
                              "Protocol": "email",
                              "TopicArn": {
                                  "Ref": ANY_VALUE
                              },
                              "Endpoint": ANY_VALUE
                          },
                          )
        )
    ##################################################
    ## </END> EC2 Imagebuilder tests
    ##################################################
   