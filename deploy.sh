#!/bin/bash

###################################################################
# Script Name     : deploy.sh
# Description     : Deploys CDK resources for AmiLifecycle project
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

# get account id
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --output text --query "Account")

# ask the user for permission to enable AWS inspector for EC2 scanning for the account
echo ""
echo "##################################"
echo ""
echo "This project requires that AWS Inspector is enabled for EC2 scanning "
echo "for account ${AWS_ACCOUNT_ID}".
echo "All accounts new to Amazon Inspector are eligible for a 15-day free trial "
echo "to evaluate the service and estimate its cost. During the trial, all eligible "
echo "Amazon Elastic Compute Cloud (EC2) instances and container images pushed to "
echo "Amazon Elastic Container Registry (ECR) are continually scanned at no cost."
echo "Please see the link below for the latest AWS Inspector pricing information:"
echo ""
echo "https://aws.amazon.com/inspector/pricing/"
echo ""
echo "##################################"
echo ""

while true; do
    read -p "Would you like to enable AWS Inspector for EC2 scanning for account: ${AWS_ACCOUNT_ID}? [y/n]" yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) echo "Thank you for your interest in the project. Without AWS Inspector enabled the deploy process will not continue." && exit;;
        * ) echo "Please answer y[yes] or n[no].";;
    esac
done

echo "############################"
echo "<START> Enable AWS Inspector2 for account: ${AWS_ACCOUNT_ID}, for resource: EC2"
echo ""
## NOTE - require aws cli aws-cli/2.7.24 +
aws inspector2 enable --account-ids ${AWS_ACCOUNT_ID} --resource-types EC2
echo ""
echo "</END> Enable AWS Inspector2"
echo ""

echo "############################"
echo "<START> EXECUTING CDK DEPLOY"
echo ""
cdk deploy --all
echo ""
echo "</END> EXECUTING CDK DEPLOY"
echo ""