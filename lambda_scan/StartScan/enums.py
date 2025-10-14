from enum import Enum

class ResponseMessage(Enum):
    SCAN_START_SUCCESS = "로그 스캔이 성공적으로 요청되었습니다."

    STATE_MACHINE_ARN_NOT_CONFIGURED = "STATE_MACHINE_ARN이 정의되지 않았습니다."

    TENANT_ID_REQUIRED = "헤더에 tenantId가 없습니다."
    CASE_ID_ACCOUNT_ID_REQUIRED = "request body에 caseId 및 accountId가 없습니다."

    ACCOUNT_NOT_FOUND = "account id를 찾을 수 없습니다."
    ROLE_ARN_NOT_FOUND = "해당 account id의 roleArn을 찾을 수 없습니다."
    ROLE_CHECK_FAILED = "assumeRole 검증을 먼저 해주세요."

    SCAN_START_ERROR = "스캔 시작 중 오류가 발생했습니다."


class ScanStatus(Enum):
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PENDING = "PENDING"


class CollectStatus(Enum):
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PENDING = "PENDING"