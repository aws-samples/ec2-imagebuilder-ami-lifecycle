#!/bin/bash -x
exec > /var/log/user-data-log.txt 2>&1
echo "export Setup environment variables"
# set up env vars
export TEST_DIR=/smoketests
export STACK_TAG=@@STACK_TAG@@
export SMOKE_TESTS_TIMEOUT=@@SMOKE_TESTS_TIMEOUT@@
export TEST_CASE_ASSETS=@@TEST_CASE_ASSETS@@
export LOG_GROUP_NAME=@@LOG_GROUP_NAME@@
export LIFECYCLE_ID=@@LIFECYCLE_ID@@
export AMI_ID=@@AMI_ID@@
export AMI_NAME=@@AMI_NAME@@
export AMI_OWNER=@@AMI_OWNER@@
export AMI_REGION=@@AMI_REGION@@
export SQS_QUEUE_URL=@@SQS_QUEUE_URL@@
export TASK_TOKEN=@@TASK_TOKEN@@
export API_KEY=@@API_KEY@@
export OPERATION_TYPE=@@OPERATION_TYPE@@
export VPC_ID=@@VPC_ID@@
export SUBNET_ID=@@SUBNET_ID@@
export SECURITY_GROUP_ID=@@SECURITY_GROUP_ID@@
export EC2_INSTANCE_PROFILE_ARN=@@EC2_INSTANCE_PROFILE_ARN@@
export CLOUDWATCH_CONF=/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
export INSTANCE_ID=$(curl http://169.254.169.254/latest/meta-data/instance-id)   
echo "export TEST_DIR=/smoketests" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export STACK_TAG=@@STACK_TAG@@" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export SMOKE_TESTS_TIMEOUT=@@SMOKE_TESTS_TIMEOUT@@" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export TEST_CASE_ASSETS=@@TEST_CASE_ASSETS@@" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export LOG_GROUP_NAME=@@LOG_GROUP_NAME@@" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export LIFECYCLE_ID=@@LIFECYCLE_ID@@" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export AMI_ID=@@AMI_ID@@" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export AMI_NAME=@@AMI_NAME@@" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export AMI_OWNER=@@AMI_OWNER@@" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export AMI_REGION=@@AMI_REGION@@" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export SQS_QUEUE_URL=@@SQS_QUEUE_URL@@" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export TASK_TOKEN=@@TASK_TOKEN@@" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export API_KEY=@@API_KEY@@" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export OPERATION_TYPE=@@OPERATION_TYPE@@" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export VPC_ID=@@VPC_ID@@" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export SUBNET_ID=@@SUBNET_ID@@" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export SECURITY_GROUP_ID=@@SECURITY_GROUP_ID@@" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export EC2_INSTANCE_PROFILE_ARN=@@EC2_INSTANCE_PROFILE_ARN@@" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export INSTANCE_ID=${INSTANCE_ID}" | sudo tee -a /etc/profile.d/smoke_tests.sh
echo "export CLOUDWATCH_CONF=/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json" | sudo tee -a /etc/profile.d/smoke_tests.sh

echo "adding scheduled shutdown so this EC2 instance can't enter a zombie state"
INSTANCE_TIMEOUT=$((${SMOKE_TESTS_TIMEOUT} + 30))
echo "EC2 instance will forecefully shutdown after ${INSTANCE_TIMEOUT} minutes"
sudo shutdown +${INSTANCE_TIMEOUT} "Smoke tests timeout"

echo "export Create working directory at ${TEST_DIR}"
# create a working dir
sudo mkdir -p ${TEST_DIR}
sudo chmod 777 ${TEST_DIR}

echo "Install and configure cloudwatch"
# install and configure CloudWatch agent
sudo yum install -y amazon-cloudwatch-agent
sudo tee -a "${CLOUDWATCH_CONF}" > /dev/null <<EOF
{
    "logs":{
        "logs_collected":{
            "files":{
                "collect_list":[
                    {
                    "file_path":"${TEST_DIR}/smoketests.log*",
                    "log_group_name":"${LOG_GROUP_NAME}",
                    "log_stream_name":"${LIFECYCLE_ID}/{instance_id}/smoketests.log"
                    },
                    {
                        "file_path":"/var/log/user-data-log.txt*",
                        "log_group_name":"${LOG_GROUP_NAME}",
                        "log_stream_name":"${LIFECYCLE_ID}/{instance_id}/var-log-user-data-log.txt"
                    }
                ]
            }
        }
    }
}
EOF
cd /
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:"${CLOUDWATCH_CONF}"
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a start
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a status

echo "Download testing assets from: ${TEST_CASE_ASSETS}"
# download assets
cd ${TEST_DIR}
aws s3 cp ${TEST_CASE_ASSETS} .
unzip *.zip

echo "Source the environment variables"
sudo chmod -R 777 ${TEST_DIR}
sudo chmod uog+r /etc/profile.d/smoke_tests.sh
source /etc/profile.d/smoke_tests.sh
env

echo "Install python dependencies"
/usr/bin/pip3 install -r requirements.txt

echo "Execute smoke tests"
# create a log file
touch "${TEST_DIR}/smoketests.log"
sudo chmod 777 "${TEST_DIR}/smoketests.log"

# execute the test case
/usr/bin/python3 smoke_tests.py