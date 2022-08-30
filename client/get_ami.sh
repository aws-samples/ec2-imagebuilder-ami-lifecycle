#!/bin/bash

###################################################################
# Script Name     : get_ami.sh
# Description     : Utility script that demonstrates how an
#                   AmiLifecycle generated AMI can be looked up 
#                   via AMI Selection criteria
# Args            :
# Author          : Damian McDonald
###################################################################


### <START> check if AWS credential variables are correctly set
if [ -z "${AWS_ACCESS_KEY_ID}" ]
then
      echo "AWS credential variable AWS_ACCESS_KEY_ID is empty."
      echo "Please see the guide below for instructions on how to configure your AWS CLI environment."
      echo "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html"
fi

if [ -z "${AWS_SECRET_ACCESS_KEY}" ]
then
      echo "AWS credential variable AWS_SECRET_ACCESS_KEY is empty."
      echo "Please see the guide below for instructions on how to configure your AWS CLI environment."
      echo "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html"
fi

if [ -z "${AWS_DEFAULT_REGION}" ]
then
      echo "AWS credential variable AWS_DEFAULT_REGION is empty."
      echo "Please see the guide below for instructions on how to configure your AWS CLI environment."
      echo "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html"
fi
### </END> check if AWS credential variables are correctly set

# version options
LATEST="latest"
ANY="any"
CREATED="ami-creation"
PATCHED="ami-patch"

# event options
AMI_WITH_OS_HARDENING="AMI_WITH_OS_HARDENING"
SMOKE_TESTED="SMOKE_TESTED"
VULNERABILITY_SCANNED="VULNERABILITY_SCANNED"
QA_CERTIFICATION_REQUESTED="QA_CERTIFICATION_REQUESTED"
QA_CERTIFIED="QA_CERTIFIED"
PRODUCTION_APPROVED="PRODUCTION_APPROVED"

# dynamic values
STACK_TAG=$(git rev-parse --abbrev-ref HEAD)
COMMIT_REF=$(git rev-parse HEAD)

echo "Calling cli_ami_selection.py with the following params."
echo ""
echo "  --stack_tag=${STACK_TAG}"
echo "  --ami_semver=${LATEST}"
echo "  --lifecycle_event=${AMI_WITH_OS_HARDENING}"
echo "  --region=${AWS_DEFAULT_REGION}"
echo "  --product_ver=${ANY}"
echo "  --product_name=${ANY}"
echo "  --commit_ref=${ANY}"
echo "  --lifecycle_type=${ANY}"
echo ""

python3 cli_ami_selection.py \
    --stack_tag=${STACK_TAG} \
    --ami_semver=${LATEST} \
    --lifecycle_event=${AMI_WITH_OS_HARDENING} \
    --region=${AWS_DEFAULT_REGION} \
    --product_ver=${ANY} \
    --product_name=${ANY} \
    --commit_ref=${ANY} \
    --lifecycle_type=${ANY}