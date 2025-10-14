import json
import boto3
import os
from datetime import datetime
from botocore.exceptions import ClientError
from dynamodb_repository import DynamoDBRepository

# ====== STS AssumeRole ======
def _assume_session(role_arn: str, session_name="list-regions"):
    sts = boto3.client("sts")
    kwargs = {"RoleArn": role_arn, "RoleSessionName": session_name}
    creds = sts.assume_role(**kwargs)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )

# ====== 계정 기준 '사용 가능한' 리전 목록 ======
def _enabled_regions(sess: boto3.Session) -> list[str]:
    ec2 = sess.client("ec2", region_name="us-east-1")
    resp = ec2.describe_regions(AllRegions=True)
    regions = [
        r["RegionName"]
        for r in resp.get("Regions", [])
        if r.get("OptInStatus") in ("opt-in-not-required", "opted-in")
    ]
    regions.sort()
    return regions

# ====== 핸들러 ======
def handler(event, context=None):
    try:
        # 필수 파라미터 검증
        tenant_id = event.get("tenant_id")
        case_id = event.get("case_id")
        account_id = event.get("account_id")
        role_arn = event.get("role_arn")

        if not all([tenant_id, case_id, account_id, role_arn]):
            raise ValueError("tenant_id, case_id, account_id, role_arn are required")

        # DynamoDB repository 초기화
        repo = DynamoDBRepository()

        # 계정 정보 확인
        account_info = repo.get_account(tenant_id, case_id, account_id)
        if not account_info:
            raise ValueError(f"Account not found: tenant_id={tenant_id}, case_id={case_id}, account_id={account_id}")

        # 1) 고객 역할로 Assume
        cust_sess = _assume_session(role_arn)

        # 2) 고객 계정 ID 확인(검증)
        sts_cust = cust_sess.client("sts")
        verified_account_id = sts_cust.get_caller_identity()["Account"]

        if verified_account_id != account_id:
            raise ValueError(f"Account ID mismatch: expected {account_id}, got {verified_account_id}")

        # 3) 고객 계정 기준 '사용 가능 리전' 조회
        regions = _enabled_regions(cust_sess)

        # 4) scan metadata 생성 (RUNNING)
        started_at = datetime.now().isoformat()

        # Atomic Counter로 순차 scan_id 생성 (1, 2, 3, ...)
        scan_id = repo.get_next_scan_id()

        scan_metadata = repo.create_scan_metadata(
            scan_id=scan_id,
            tenant_id=tenant_id,
            case_id=case_id,
            account_id=account_id,
            started_at=started_at,
            status='RUNNING'
        )

        # 5) 다음 단계로 넘길 페이로드 반환
        # Step Functions Map을 위해 각 리전을 객체 배열로 변환
        region_items = []
        for region in regions:
            item = {
                "region": region,
                "scan_id": scan_id,
                "tenant_id": tenant_id,
                "case_id": case_id,
                "account_id": account_id,
                "role_arn": role_arn
            }
            region_items.append(item)

        out = {
            "scan_id": scan_id,
            "tenant_id": tenant_id,
            "case_id": case_id,
            "account_id": account_id,
            "role_arn": role_arn,
            "regions": region_items,  # Map 입력용
        }

        return out

    except ClientError as e:
        # Step Functions Task 실패로 올려도 되고, API 응답용이면 포맷 바꿔도 됨
        raise
    except Exception as e:
        # 디버깅 편의를 위해 예외 그대로 던지거나, 아래처럼 메시지만 던져도 됨
        raise
        