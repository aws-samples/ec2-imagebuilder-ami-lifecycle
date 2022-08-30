#!/usr/bin/env python3
import os

from aws_cdk import core as cdk

# For consistency with TypeScript code, `cdk` is the preferred import name for
# the CDK's core module.  The following line also imports it as `core` for use
# with examples from the CDK Developer's Guide, which are in the process of
# being updated to use `cdk`.  You may delete this import if you don't need it.
from aws_cdk import core

from stacks.network.network import NetworkStack
from stacks.imagebuilder.image_builder import ImageBuilderStack
from stacks.amilifecycle.vmdk_export import VmdkExportStack
from stacks.amilifecycle.ami_lifecycle_tagger import AmiLifecycleTaggerStack
from stacks.amilifecycle.ami_lifecycle import AmiLifecycleStack

app = core.App()

network_stack = NetworkStack(
    app, 
    'AmiLifecycleNetwork',
    # If you don't specify 'env', this stack will be environment-agnostic.
    # Account/Region-dependent features and context lookups will not work,
    # but a single synthesized template can be deployed anywhere.

    # Uncomment the next line to specialize this stack for the AWS Account
    # and Region that are implied by the current CLI configuration.

    env=core.Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'), region=os.getenv('CDK_DEFAULT_REGION')),

    # Uncomment the next line if you know exactly what Account and Region you
    # want to deploy the stack to. */

    #env=core.Environment(account='account_id', region='us-east-1'),

    # For more information, see https://docs.aws.amazon.com/cdk/latest/guide/environments.html
)

image_builder_stack = ImageBuilderStack(
    app, 
    'AmiLifecycleImageBuilder',
    vpc=network_stack.vpc,
    vpc_private_subnet_id=network_stack.vpc_private_subnet_id,
    env=core.Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'), region=os.getenv('CDK_DEFAULT_REGION'))
)

vmdk_export_stack = VmdkExportStack(
    app, 
    'VmdkExport',
    env=core.Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'), region=os.getenv('CDK_DEFAULT_REGION'))
)

AmiLifecycleTaggerStack(
    app, 
    'AmiLifecycleTagger',
    env=core.Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'), region=os.getenv('CDK_DEFAULT_REGION'))
)

stack_outputs = {}
stack_outputs['vpc'] = network_stack.vpc
stack_outputs['imagebuilder_instance_profile_arn'] = image_builder_stack.image_builder_instance_profile_arn
stack_outputs['imagebuilder_instance_profile_name'] = image_builder_stack.image_builder_instance_profile_name
stack_outputs['imagebuilder_subnet_id'] = network_stack.vpc_private_subnet_id
stack_outputs['imagebuilder_topic_arn'] = image_builder_stack.image_builder_sns_topic_arn
stack_outputs['imagebuilder_security_group'] = image_builder_stack.image_builder_security_group_id
stack_outputs['kms_key_arn'] = image_builder_stack.image_builder_kms_key_arn
stack_outputs['vmdk_export_bucket_arn'] = vmdk_export_stack.bucket_arn


AmiLifecycleStack(
    app, 
    'AmiLifecycle',
    stack_outputs=stack_outputs,
    env=core.Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'), region=os.getenv('CDK_DEFAULT_REGION'))
)

app.synth()
