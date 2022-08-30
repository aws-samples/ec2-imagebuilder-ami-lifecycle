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
def ami_lifecycle_tagger_stack(request):
    request.cls.cfn_template = tc.BaseTestCase.load_stack_template("AmiLifecycleTagger")


@pytest.mark.usefixtures('synth', 'ami_lifecycle_tagger_stack')
class TestAmiLifecycleTaggerStack(tc.BaseTestCase):
    """
        Test case for AmiLifecycleTaggerStack
    """

    def test_ami_tags_crossaccount_role_exists(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, "ami-lifecycle-tagger-role"))


    def test_ami_tags_crossaccount_role(self):
        expect(self.cfn_template).to(have_resource(
            self.iam_role,
            {
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Action": "sts:AssumeRole",
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": f"arn:aws:iam::{core.Aws.ACCOUNT_ID}:root"
                            }
                        }
                    ]
                }
            }
        ))


    def test_ami_tags_crossaccount_policy_role(self):
        expect(self.cfn_template).to(have_resource(
            self.iam_policy,
            {
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Action": [
                                "ec2:DescribeTags",
                                "ec2:DescribeImageAttribute",
                                "ec2:DescribeImages",
                                "ec2:DeleteTags",
                                "ec2:CreateTags",
                                "ec2:RegisterImage",
                                "ec2:ModifyImageAttribute"
                            ],
                            "Effect": "Allow",
                            "Resource": "*"
                        }
                    ]
                }
            }
        ))