#!/bin/bash

######################################################################
# Script Name     : destroy.sh
# Description     : Destroys CDK resources of the AmiLifecycle project
# Args            :
# Author          : Damian McDonald
######################################################################

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

# get account id
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --output text --query "Account")

# ask the user for permission to enable AWS inspector for EC2 scanning for the account
echo ""
echo "##################################"
echo ""
echo "This project has enabled AWS Inspector for EC2 scanning for account ${AWS_ACCOUNT_ID}".
echo "AWS Inspector for EC2 scanning for account ${AWS_ACCOUNT_ID} can be disabled"
echo "during destruction of this project."
echo "Please see the link below for the latest AWS Inspector pricing information:"
echo ""
echo "https://aws.amazon.com/inspector/pricing/"
echo ""
echo "##################################"
echo ""

while true; do
    read -p "Would you like to disable AWS Inspector for EC2 scanning for account: ${AWS_ACCOUNT_ID}? [y/n]" yn
    case $yn in
        [Yy]* ) DISABLE_INSPECTOR="TRUE" && break;;
        [Nn]* ) DISABLE_INSPECTOR="FALSE" && break;;
        * ) echo "Please answer y[yes] or n[no].";;
    esac
done

if [ -z "${DISABLE_INSPECTOR}" ]
then
      echo "DISABLE_INSPECTOR variable is empty."
      exit 999
fi

if [ "${DISABLE_INSPECTOR}" == "TRUE" ]
then
      echo "############################"
      echo "<START> Disable AWS Inspector2 for account: ${AWS_ACCOUNT_ID}, for resource: EC2"
      echo ""
      ## NOTE - require aws cli aws-cli/2.7.24 +
      aws inspector2 disable --account-ids ${AWS_ACCOUNT_ID} --resource-types EC2
      echo ""
      echo "</END> Disable AWS Inspector2"
      echo ""
fi

echo "<START> EXECUTING CDK DESTROY"
echo ""
cdk destroy --all
echo ""
echo "</END> EXECUTING CDK DESTROY"
echo "############################"