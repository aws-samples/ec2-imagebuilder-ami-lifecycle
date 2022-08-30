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
def vmdk_export_stack(request):
    request.cls.cfn_template = tc.BaseTestCase.load_stack_template("VmdkExport")


@pytest.mark.usefixtures('synth', 'vmdk_export_stack')
class TestVmdkExportStack(tc.BaseTestCase):
    """
        Test case for VmdkExportStack
    """

    def test_vmimport_role(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.iam_role, "vm-import-role"))


    def test_vmimport_policy_role(self):
        expect(self.cfn_template).to(have_resource(
            self.iam_role,
            {
                "AssumeRolePolicyDocument": {
                "Statement": [
                    {
                    "Action": "sts:AssumeRole",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "vmie.amazonaws.com"
                    },
                    "Condition": {
                        "StringEquals": {
                        "sts:Externalid": [
                            "vmimport"
                        ]
                        }
                    }
                    }
                ],
                "Version": "2012-10-17"
                }
            }
        ))


    def test_vmimport_ec2_policy_role(self):
        expect(self.cfn_template).to(have_resource(
            self.iam_policy,
            {
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Action": [
                                "ec2:CopySnapshot",
                                "ec2:Describe*",
                                "ec2:ModifySnapshotAttribute",
                                "ec2:RegisterImage",
                                "ec2:CreateTags",
                                "ec2:ExportImage"
                            ],
                            "Effect": "Allow",
                            "Resource": "*"
                        }
                    ]
                }
            }
        ))


    def test_vmimport_s3_policy_role(self):
        expect(self.cfn_template).to(have_resource(
            self.iam_policy,
            {
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Action": [
                                "s3:GetObject*",
                                "s3:GetBucket*",
                                "s3:List*",
                                "s3:DeleteObject*",
                                "s3:PutObject",
                                "s3:Abort*"
                            ],
                            "Effect": "Allow",
                            "Resource": [
                                ANY_VALUE,
                                ANY_VALUE
                            ]
                        }
                    ]
                }
            }
        ))

   