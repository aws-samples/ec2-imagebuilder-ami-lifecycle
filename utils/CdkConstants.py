class CdkConstants():

    ### NETWORK STACK OUTPUT NAMES ###
    VPC_ID = "vpcId"
    VPC_PUBLIC_SUBNET_ID = "vpcPublicSubnetId"
    VPC_PRIVATE_SUBNET_ID = "vpcPrivateSubnetId"

    ### IMAGEBUILDER STACK OUTPUT NAMES ###
    IMAGEBUILDER_PIPELINE_ARN = "pipelineArn"
    EC2_INSTANCE_PROFILE_ARN = "ec2InstanceProfileArn"
    EC2_INSTANCE_PROFILE_NAME = "ec2InstanceProfileName"
    IMAGEBUILDER_TOPIC_ARN = "imagebuilderTopicArn"
    IMAGEBUILDER_SECURITY_GROUP_ID = "imagebuilderSecurityGroupId"
    IMAGEBUILDER_KMS_KEY_ARN = "imagebuilderKmsKeyArn"

    ### AMILIFECYCLETAGGER STACK OUTPUT NAMES ###
    CROSS_ACCOUNT_TAGGER_ROLE_ARN = "crossAccountTaggerRoleArn"

    ### VMDKEXPORT STACK OUTPUT NAMES ###
    VMDK_EXPORT_BUCKET_ARN = "vmdkExportBucketArn"

    ### AMILIFECYCLE STACK OUTPUT NAMES ###
    AMIORCHESTRATOR_CFN_CA_READONLY = "amiOrchestratorCfnCAReadOnly"
    AMIORCHESTRATOR_API_GATEWAY_ID = "amiOrchestratorApiGatewayId"
    AMIORCHESTRATOR_API_GATEWAY_ENDPOINT = "amiOrchestratorApiGatewayEndpoint"
    AMIORCHESTRATOR_API_GATEWAY_STAGENAME = "amiOrchestratorApiGatewayStageName"
    AMIORCHESTRATOR_API_GATEWAY_URL = "amiOrchestratorApiGatewayUrl"
    AMIORCHESTRATOR_API_GATEWAY_ARN = "amiOrchestratorApiGatewayArn"
    AMIORCHESTRATOR_NOTIFICATION_TOPIC_ARN = "amiOrchestratorNotificationTopicArn"
    AMISELECTION_CA_READONLY = "amiSelectionCAReadOnly"
    AMISELECTION_TABLENAME = "amiSelectionTableName"
    AMILIFECYCLE_PATCH_COMPONENT_BUCKET = "amiLifecyclePatchComponentBucket"
    AMILIFECYCLE_AMI_BUILD_STATEMACHINE_NAME = "lifeCycleAmiBuildStateMachineName"
    AMILIFECYCLE_SMOKE_TESTS_STATEMACHINE_NAME = "lifeCycleSmokeTestsStateMachineName"
    AMILIFECYCLE_VULNERABILITY_SCANS_STATEMACHINE_NAME = "lifeCycleVulnerabilityScansStateMachineName"
    AMILIFECYCLE_QA_CERTIFICATION_STATEMACHINE_NAME = "lifeCycleQACertificationStateMachineName"
    AMILIFECYCLE_AMI_PATCH_STATEMACHINE_NAME = "lifeCycleAmiPatchStateMachineName"
    AMILIFECYCLE_MARK_FOR_PRODUCTION_STATEMACHINE_NAME = "lifeCycleMarkForProductionStateMachineName"
    AMILIFECYCLE_AMI_BACKUP_BUCKET = "amiBackupBucket"