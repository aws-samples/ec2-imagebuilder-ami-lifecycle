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
def ami_lifecycle_stack(request):
    request.cls.cfn_template = tc.BaseTestCase.load_stack_template("AmiLifecycle")


@pytest.mark.usefixtures('synth', 'ami_lifecycle_stack')
class TestAmiLifecycleStack(tc.BaseTestCase):
    """
        Test case for AmiLifecycleStack
    """

    config = CdkUtils.get_project_settings()

    # # Admin permissions
    def test_no_admin_permissions(self):
        assert json.dumps(self.cfn_template).count(':iam::aws:policy/AdministratorAccess') == 0

    # test KMS
    def test_kms_key_rotation_existence(self):
        expect(self.cfn_template).to(have_resource(self.kms_key, {
            "EnableKeyRotation": True
        }))

    def test_kms_key_existence(self):
        expect(self.cfn_template).to(contain_metadata_path(self.kms_key, f'Resource'))

    # log groups
    def test_api_gateway_access_log_group_exists(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.cw_log_group, f'amiOrchestratorApiGatewayLogGroup'))

    def test_api_gateway_access_log_group_retention(self):
        expect(self.cfn_template).to(have_resource(self.cw_log_group, {
            "RetentionInDays": 14
        }))

    def test_event_notifications_log_group_exists(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.cw_log_group, f'amiOrchestratorEventNotificationsLogGroup'))

    def test_event_notifications_log_group_retention(self):
        expect(self.cfn_template).to(have_resource(self.cw_log_group, {
            "RetentionInDays": 14
        }))

    # test custom resource

    def test_apicreate_custom_resource(self):
        expect(self.cfn_template).to(contain_metadata_path(self.custom_cfn_resource, f'ApiCreateCusRes'))

    def test_create_api_secrets_custom_resource(self):
        expect(self.cfn_template).to(contain_metadata_path(self.custom_cfn_resource, f'amiLifecycleSecretsManagerCR'))

    # test roles

    def test_event_notifications_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcEventNotificationsLambdaRole"))

    def test_apicreate_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"ApiCreateLmbRole"))

    def test_api_secrets_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"amiLifecycleSecretsManagerLambdaRole"))

    def test_api_get_stauts_by_lifecycle_id_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"ApiGetStatusByLifecycleIdLambdaRole"))

    def test_api_get_stauts_by_stack_tag_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"ApiGetStatusByStackTagLambdaRole"))

    def test_api_lifecycle_create_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"ApiCreateLifecycleLambdaRole"))

    def test_api_lifecycle_create_update_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"ApiCreateUpdateLifecycleLambdaRole"))

    def test_api_lifecycle_create_timeline_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"ApiCreateTimelineLambdaRole"))

    def test_api_lifecycle_create_markproduction_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"ApiCreateMarkForProdLifecycleLambdaRole"))

    def test_api_lifecycle_create_qacertify_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"ApiCreateQACertifyLifecycleLambdaRole"))

    def test_api_lifecycle_patch_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"ApiPatchLifecycleLambdaRole"))

    def test_api_lifecycle_patch_update_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"ApiPatchUpdateLifecycleLambdaRole"))

    def test_api_lifecycle_patch_timeline_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"ApiPatchTimelineLambdaRole"))

    def test_api_lifecycle_patch_markproduction_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"ApiPatchMarkForProdLifecycleLambdaRole"))

    def test_api_lifecycle_create_receiver_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"ApiCreateReceiverLambdaRole"))

    def test_api_lifecycle_patch_receiver_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"ApiPatchReceiverLambdaRole"))

    def test_api_lifecycle_error_receiver_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"ApiErrorReceiverLambdaRole"))

    def test_ami_orchestrator_dynamodb_role(self):
        expect(self.cfn_template).to(contain_metadata_path(
                self.iam_role, f"amiOrchestratorDynamodbCARole"
            )
        )

    def test_cfn_ca_role(self):
        expect(self.cfn_template).to(contain_metadata_path(
                self.iam_role, f"amiOrchestratorCfnCARole"
            )
        )
    # test lambdas

    def test_event_notifications_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcEventNotificationsLambda"))

    def test_apicreate_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"ApiCreateLmb"))

    def test_api_secrets_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"amiLifecycleSecretsManagerLambda"))

    def test_api_get_stauts_by_lifecycle_id_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"ApiGetStatusByLifecycleIdLambda"))

    def test_api_get_stauts_by_stack_tag_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"ApiGetStatusByStackTagLambda"))

    def test_api_lifecycle_create_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"ApiCreateLifecycleLambda"))

    def test_api_lifecycle_create_update_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"ApiCreateUpdateLifecycleLambda"))

    def test_api_lifecycle_create_timeline_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"ApiCreateTimelineLambda"))

    def test_api_lifecycle_create_markproduction_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"ApiCreateMarkForProdLifecycleLambda"))

    def test_api_lifecycle_create_qacertify_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"ApiCreateQACertifyLifecycleLambda"))

    def test_api_lifecycle_patch_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"ApiPatchLifecycleLambda"))

    def test_api_lifecycle_patch_update_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"ApiPatchUpdateLifecycleLambda"))

    def test_api_lifecycle_patch_timeline_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"ApiPatchTimelineLambda"))

    def test_api_lifecycle_patch_markproduction_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"ApiPatchMarkForProdLifecycleLambda"))

    def test_api_lifecycle_create_receiver_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"ApiCreateReceiverLambda"))

    def test_api_lifecycle_patch_receiver_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"ApiPatchReceiverLambda"))

    def test_api_lifecycle_error_receiver_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"ApiErrorReceiverLambda"))
    
    # test buckets

    def test_patch_component_bucket_created(self):
        expect(self.cfn_template).to(contain_metadata_path(self.s3_bucket, f'AmiPatchComponentS3Bucket'))

    # test topic

    def test_sns_topic_exists(self):
        expect(self.cfn_template).to(contain_metadata_path(self.sns_topic, f"AmiOrchestratorTopic"))

    # test queue

    def test_sqs_creation_receiver_exists(self):
        expect(self.cfn_template).to(contain_metadata_path(self.sqs_queue, f"AmiCreationReceiverQueue"))

    def test_sqs_patch_receiver_exists(self):
        expect(self.cfn_template).to(contain_metadata_path(self.sqs_queue, f"AmiPatchReceiverQueue"))

    def test_sqs_error_receiver_exists(self):
        expect(self.cfn_template).to(contain_metadata_path(self.sqs_queue, f"AmiErrorReceiverQueue"))

    # test dynamodb
    def test_state_dynamodb_lifecycle_state_exists(self):
        expect(self.cfn_template).to(contain_metadata_path(
                self.dynamodb_table, f"AmiOrchestratorTable"
            )
        )

    def test_state_dynamodb_ami_semver_exists(self):
        expect(self.cfn_template).to(contain_metadata_path(
                self.dynamodb_table, f"AmiSemverSeedTable"
            )
        )

    def test_state_dynamodb_ami_lookup_exists(self):
            expect(self.cfn_template).to(contain_metadata_path(
                self.dynamodb_table, f"AmiLookupTable"
            )
        )

    # api gateway lambda permissions
    def test_api_gateway_lambda_permissions_count(self):
        assert json.dumps(self.cfn_template).count(
            'AWS::Lambda::Permission'
        ) == 15

    ##########################################################
    # <START> AMI BUILD lifecycle tests
    ##########################################################

    # /** ami build lambda roles **/

    def test_ami_build_entry_point_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcBuildEntryPointLambdaRole"))

    def test_ami_build_poll_ami_status_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcBuildPollAmiStatusLambdaRole"))

    def test_ami_build_ami_details_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcBuildAmiDetailsLambdaRole"))

    def test_ami_build_notify_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcBuildNotifyLambdaRole"))

    # test lambdas

    def test_ami_build_entry_point_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcBuildEntryPointLambda"))

    def test_ami_build_poll_ami_status_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcBuildPollAmiStatusLambda"))

    def test_ami_build_ami_details_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcBuildAmiDetailsLambda"))

    def test_ami_build_notify_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcBuildNotifyLambda"))

    # test state machine

    def test_ami_build_state_machine_loggroup_retention(self):
        expect(self.cfn_template).to(have_resource(self.cw_log_group, {
            "RetentionInDays": 14
        }))

    def test_ami_build_state_machine(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.state_machine, f"LifeCycleAmiBuildStateMachineName"))


    ##########################################################
    # </END> AMI BUILD lifecycle tests
    ##########################################################


    ##########################################################
    # <START> SMOKE TESTS lifecycle tests
    ##########################################################

    # /** smoke tests lambda roles **/

    def test_smoke_tests_entry_point_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcSmokeTestsEntryPointLambdaRole"))

    def test_smoke_tests_test_executor_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcSmokeTestsExecutorLambdaRole"))

    def test_smoke_tests_tear_down_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcSmokeTestsTearDownLambdaRole"))

    def test_smoke_tests_notify_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcSmokeTestsNotifyLambdaRole"))

    # test lambdas

    def test_smoke_tests_entry_point_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcSmokeTestsEntryPointLambda"))

    def test_smoke_tests_test_executor_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcSmokeTestsExecutorLambda"))

    def test_smoke_tests_tear_down_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcSmokeTestsTearDownLambda"))

    def test_smoke_tests_notify_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcSmokeTestsNotifyLambda"))

    # test state machine

    def test_smoke_tests_state_machine_loggroup_retention(self):
        expect(self.cfn_template).to(have_resource(self.cw_log_group, {
            "RetentionInDays": 14
        }))

    def test_smoke_tests_state_machine(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.state_machine, f"LifeCycleSmokeTestsStateMachineName"))

    # smoke test queue
    def test_smoke_tests_test_executor_queue(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.sqs_queue, f"AmiLcSmokeTestsExecutorQueue"))

    ##########################################################
    # </END> SMOKE TESTS lifecycle tests
    ##########################################################


    ##########################################################
    # <START> VULNERABILITY SCANS lifecycle tests
    ##########################################################

    # /** vulnerability scans lambda roles **/

    def test_vulnerability_scans_entry_point_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcVulnerabilityScansEntryPointLambdaRole"))

    def test_vulnerability_scans_launch_instance_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcVulnerabilityScansLaunchInstanceLambdaRole"))

    def test_vulnerability_scans_poll_status_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcVulnerabilityScansPollStatusLambdaRole"))

    def test_vulnerability_scans_get_findings_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcVulnerabilityScansFindingsLambdaRole"))

    def test_vulnerability_scans_publish_metrics_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcVulnerabilityScansPublishMetricsLambdaRole"))

    def test_vulnerability_scans_tear_down_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcVulnerabilityScansTearDownLambdaRole"))

    def test_vulnerability_scans_notify_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcVulnerabilityScansNotifyLambdaRole"))

    # test lambdas

    def test_vulnerability_scans_entry_point_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcVulnerabilityScansEntryPointLambda"))

    def test_vulnerability_scans_launch_instance_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcVulnerabilityScansLaunchInstanceLambda"))

    def test_vulnerability_scans_poll_status_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcVulnerabilityScansPollStatusLambda"))

    def test_vulnerability_scans_get_findings_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcVulnerabilityScansFindingsLambda"))

    def test_vulnerability_scans_publish_metrics_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcVulnerabilityScansPublishMetricsLambda"))

    def test_vulnerability_scans_tear_down_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcVulnerabilityScansTearDownLambda"))

    def test_vulnerability_scans_notify_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcVulnerabilityScansNotifyLambda"))

    # test state machine

    def test_vulnerability_scans_state_machine_loggroup_retention(self):
        expect(self.cfn_template).to(have_resource(self.cw_log_group, {
            "RetentionInDays": 14
        }))

    def test_vulnerability_scans_state_machine(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.state_machine, f"LifeCycleVulnerabilityScansStateMachineName"))

    ##########################################################
    # </END> VULNERABILITY SCANS lifecycle tests
    ##########################################################


    ##########################################################
    # <START> AMI PATCH lifecycle tests
    ##########################################################

    # /** ami patch lambda roles **/

    def test_ami_patch_entry_point_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcPatchEntryPointLambdaRole"))

    def test_ami_patch_create_component_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcPatchCreateComponentLambdaRole"))

    def test_ami_patch_create_image_recipe_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcPatchCreateImageRecipeLambdaRole"))

    def test_ami_patch_create_imagepipeline_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcPatchCreateImagePipelineLambdaRole"))

    def test_ami_patch_ami_poll_status_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcPatchAmiDetailsLambdaRole"))

    def test_ami_patch_dynamic_delete_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcPatchDeleteDynamicLambdaRole"))

    def test_ami_patch_notify_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcPatchNotifyLambdaRole"))

    # test lambdas

    def test_ami_patch_entry_point_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcPatchEntryPointLambda"))

    def test_ami_patch_create_component_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcPatchCreateComponentLambda"))

    def test_ami_patch_create_image_recipe_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcPatchCreateImageRecipeLambda"))

    def test_ami_patch_create_imagepipeline_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcPatchCreateImagePipelineLambda"))

    def test_ami_patch_ami_poll_status_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcPatchAmiDetailsLambda"))

    def test_ami_patch_dynamic_delete_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcPatchDeleteDynamicLambda"))

    def test_ami_patch_notify_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcPatchNotifyLambda"))


    # test state machine

    def test_ami_patch_state_machine_loggroup_retention(self):
        expect(self.cfn_template).to(have_resource(self.cw_log_group, {
            "RetentionInDays": 14
        }))

    def test_ami_patch_state_machine(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.state_machine, f"LifeCycleAmiPatchStateMachineName"))

    ##########################################################
    # </END> AMI PATCH lifecycle tests
    ##########################################################


    ##########################################################
    # <START> QA CFERTIFICATION REQUEST lifecycle tests
    ##########################################################

    # /** qa certification request lambda roles **/

    def test_qa_certification_request_entry_point_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcQACertifyEntryPointLambdaRole"))

    def test_qa_certification_request_ami_status_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcQACertifyAmiStatusLambdaRole"))

    def test_qa_certification_request_vmdk_export_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcQACertifyVmdkExportLambdaRole"))

    def test_qa_certification_request_vmdk_status_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcQACertifyPollVmdkStatusLambdaRole"))

    def test_qa_certification_request_generate_url_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcQACertifyGenerateUrlLambdaRole"))

    def test_qa_certification_request_notify_external_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcQACertifyNotifyQALambdaRole"))

    def test_qa_certification_request_notify_lambda_role(self):
        expect(self.cfn_template).to(contain_metadata_path(self.iam_role, f"AmiLcQACertifyNotifyLambdaRole"))

    # test lambdas

    def test_qa_certification_request_entry_point_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcQACertifyEntryPointLambda"))

    def test_qa_certification_request_ami_status_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcQACertifyAmiStatusLambda"))

    def test_qa_certification_request_vmdk_export_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcQACertifyVmdkExportLambda"))

    def test_qa_certification_request_vmdk_status_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcQACertifyPollVmdkStatusLambda"))

    def test_qa_certification_request_generate_url_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcQACertifyGenerateUrlLambda"))

    def test_qa_certification_request_notify_external_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcQACertifyNotifyQALambda"))

    def test_qa_certification_request_notify_lambda(self):
        expect(self.cfn_template).to(contain_metadata_path(self.lambda_, f"AmiLcQACertifyNotifyLambda"))


    # test state machine

    def test_qa_certification_request_state_machine_loggroup_retention(self):
        expect(self.cfn_template).to(have_resource(self.cw_log_group, {
            "RetentionInDays": 14
        }))

    def test_qa_certification_request_state_machine(self):
        expect(self.cfn_template).to(
            contain_metadata_path(self.state_machine, f"LifeCycleQACertificationStateMachineName"))

    ##########################################################
    # </END> QA CFERTIFICATION REQUEST lifecycle tests
    ##########################################################