import json
from enums import ResponseMessage


class ApiResponse:
    def __init__(self, status_code, body, headers=None):
        self.status_code = status_code
        self.body = body
        self.headers = headers or {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }

    def to_dict(self):
        return {
            'statusCode': self.status_code,
            'headers': self.headers,
            'body': json.dumps(self.body, default=str, ensure_ascii=False)
        }


class ErrorResponse(ApiResponse):
    def __init__(self, status_code, error_message, details=None):
        body = {
            'status_code': status_code,
            'message': error_message
            }
        if details:
            body['details'] = details
        super().__init__(status_code, body)


class ScanStartSuccessResponse(ApiResponse):
    def __init__(self, scan_id, tenant_id, case_id, account_id, execution_arn, execution_name):
        body = {
            'status_code': 202,
            'message': ResponseMessage.SCAN_START_SUCCESS.value,
            'data': {
                'scanId': scan_id,
                'tenantId': tenant_id,
                'caseId': case_id,
                'accountId': account_id,
                'execution_arn': execution_arn,
                'execution_name': execution_name
            }
        }
        super().__init__(202, body)


def missing_config_error(config_name=None):
    if config_name:
        return ErrorResponse(500, ResponseMessage.STATE_MACHINE_ARN_NOT_CONFIGURED.value)
    return ErrorResponse(500, ResponseMessage.STATE_MACHINE_ARN_NOT_CONFIGURED.value)


def missing_parameter_error(param_name, location='body'):
    if param_name == 'tenantId' and location == 'headers':
        return ErrorResponse(400, ResponseMessage.TENANT_ID_REQUIRED.value)
    return ErrorResponse(400, ResponseMessage.TENANT_ID_REQUIRED.value)


def missing_parameters_error(param_names):
    if set(param_names) == {'caseId', 'accountId'}:
        return ErrorResponse(400, ResponseMessage.CASE_ID_ACCOUNT_ID_REQUIRED.value)
    return ErrorResponse(400, ResponseMessage.CASE_ID_ACCOUNT_ID_REQUIRED.value)


def account_not_found_error():
    return ErrorResponse(404, ResponseMessage.ACCOUNT_NOT_FOUND.value)


def role_arn_not_found_error():
    return ErrorResponse(400, ResponseMessage.ROLE_ARN_NOT_FOUND.value)


def role_check_failed_error():
    return ErrorResponse(403, ResponseMessage.ROLE_CHECK_FAILED.value)


def internal_server_error(message=None, details=None):
    error_message = message or ResponseMessage.SCAN_START_ERROR.value
    return ErrorResponse(500, error_message, details)
