import json
import boto3
import os
from datetime import datetime
from response_dto import (
    ScanStartSuccessResponse,
    missing_config_error,
    missing_parameter_error,
    missing_parameters_error,
    account_not_found_error,
    role_arn_not_found_error,
    role_check_failed_error,
    internal_server_error
)
from dynamodb_repository import DynamoDBRepository
from enums import ResponseMessage

db_repo = DynamoDBRepository()

def lambda_handler(event, context):
    state_machine_arn = os.environ.get('STATE_MACHINE_ARN')
    if not state_machine_arn:
        return missing_config_error('STATE_MACHINE_ARN').to_dict()

    # 헤더에서 tenantId 추출
    headers = event.get('headers', {})
    tenant_id = headers.get('tenant_id') or headers.get('tenant_id')

    if not tenant_id:
        return missing_parameter_error('tenant_id', 'headers').to_dict()

    # Request body 파싱
    body = {}
    if event.get('body'):
        body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']

    case_id = body.get('case_id')
    account_id = body.get('account_id')

    # 필수 파라미터 검증
    if not case_id or not account_id:
        return missing_parameters_error(['case_id', 'account_id']).to_dict()

    try:
        # DynamoDB에서 account 정보 조회
        account_item = db_repo.get_account(tenant_id, case_id, account_id)

        # Account가 존재하지 않는 경우
        if not account_item:
            return account_not_found_error().to_dict()

        # roleArn 검증
        role_arn = account_item.get('roleArn')
        role_check = account_item.get('roleCheck', False)

        if not role_arn:
            return role_arn_not_found_error().to_dict()

        if not role_check:
            return role_check_failed_error().to_dict()

        # Scan ID 생성 (timestamp 기반 유니크 ID)
        scan_id = int(datetime.now().timestamp() * 1000)
        started_at = datetime.now().isoformat()

        # DynamoDB에 Scan Metadata 저장
        db_repo.create_scan_metadata(
            scan_id=scan_id,
            tenant_id=tenant_id,
            case_id=case_id,
            account_id=account_id,
            started_at=started_at,
            status='RUNNING'
        )

        # Step Functions 입력 데이터 준비
        sfn_input = {
            'scan_id': scan_id,
            'tenant_id': int(tenant_id),
            'case_id': int(case_id),
            'account_id': account_id,
            'role_arn': role_arn
        }

        # external_id가 있으면 추가
        external_id = body.get('external_id')
        if external_id:
            sfn_input['external_id'] = external_id

        # Step Functions 실행 시작
        sfn = boto3.client('stepfunctions')

        response = sfn.start_execution(
            stateMachineArn=state_machine_arn,
            name=f"scan-{scan_id}",  # execution name에 scanId 포함
            input=json.dumps(sfn_input, default=str)
        )

        execution_arn = response['execution_arn']
        execution_name = response['execution_arn'].split(':')[-1]

        return ScanStartSuccessResponse(
            scan_id=scan_id,
            tenant_id=int(tenant_id),
            case_id=int(case_id),
            account_id=account_id,
            execution_arn=execution_arn,
            execution_name=execution_name
        ).to_dict()

    except Exception as e:
        print(f"Error starting scan: {str(e)}")
        import traceback
        traceback.print_exc()

        return internal_server_error(
            message=ResponseMessage.SCAN_START_ERROR.value,
            details=str(e)
        ).to_dict()