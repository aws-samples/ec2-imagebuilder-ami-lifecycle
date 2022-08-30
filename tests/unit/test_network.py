import json

import pytest
from expects import expect

from aws_cdk import (
    core
)

from cdk_expects_matcher.CdkMatchers import contain_metadata_path
import tests.utils.base_test_case as tc
from utils.CdkUtils import CdkUtils


@pytest.fixture(scope="class")
def network_stack(request):
    request.cls.cfn_template = tc.BaseTestCase.load_stack_template(f"AmiLifecycleNetwork")


@pytest.mark.usefixtures('synth', 'network_stack')
class TestNetworkStack(tc.BaseTestCase):
    """
        Test case for NetworkStack
    """

    config = CdkUtils.get_project_settings()

    ##################################################
    ## <START> AWS VPC element tests
    ##################################################

    def test_vpc_created(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.vpc, "ami-lifecycle-vpc"
            )
        )

    def test_secure_proxy_vpc_subnets_count(self):
        assert json.dumps(self.cfn_template).count('\"AWS::EC2::Subnet\"') == 2

    def test_secure_proxy_vpc_subnets_rt_assoc_count(self):
        assert json.dumps(self.cfn_template).count('\"AWS::EC2::SubnetRouteTableAssociation\"') == 2

    def test_secure_proxy_vpc_subnets_nat_gw_count(self):
        assert json.dumps(self.cfn_template).count('\"AWS::EC2::NatGateway\"') == 2

    def test_secure_proxy_vpc_subnets_nat_gw_count(self):
        assert json.dumps(self.cfn_template).count('\"AWS::EC2::EIP\"') == 1
    ##################################################
    ## </END> AWS VPC element tests
    ##################################################