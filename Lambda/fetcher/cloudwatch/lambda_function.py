
import os
import json
import gzip
import time
import random
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import boto3
from botocore.exceptions import ClientError

# ===== 로깅 설정 =====
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ===== 환경변수 =====
AWS_REGION = os.getenv("AWS_REGION", "ap-northeast-2")
SOURCE_ACCOUNT_ROLE_ARN = os.getenv("SOURCE_ACCOUNT_ROLE_ARN", "{SOURCE_ACCOUNT_ROLE_ARN 입력}")
BUCKET = os.getenv("BUCKET", "cirfrawtest")
PREFIX = os.getenv("PREFIX", "cloudwatch-assume")
CHECKPOINT_FILE = "/tmp/checkpoint.json"

# ===== 재시도 로직 =====
def retry_call(fn, max_attempts=5, base=1, *args, **kwargs):
    """Throttling 에러만 지수 백오프 + jitter로 재시도"""
    attempt = 0
    while True:
        try:
            return fn(*args, **kwargs)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            attempt += 1

            if error_code in ['ThrottlingException', 'TooManyRequestsException', 'ProvisionedThroughputExceededException']:
                if attempt >= max_attempts:
                    logger.error(f"Max retry attempts reached for {fn.__name__}")
                    raise
                sleep_time = base * (2 ** (attempt - 1)) + random.uniform(0, 1)
                logger.warning(f"Throttled, retrying {fn.__name__} in {sleep_time:.2f}s (attempt {attempt}/{max_attempts})")
                time.sleep(sleep_time)
            else:
                logger.error(f"Non-retryable error in {fn.__name__}: {error_code}")
                raise

# ===== Boto3 클라이언트 초기화 =====
def init_clients():
    """CloudWatch Logs 및 S3 클라이언트 초기화"""
    sts_client = boto3.client("sts", region_name=AWS_REGION)

    if not SOURCE_ACCOUNT_ROLE_ARN:
        logger.error("SOURCE_ACCOUNT_ROLE_ARN is required")
        raise RuntimeError("SOURCE_ACCOUNT_ROLE_ARN environment variable must be set")

    logger.info(f"Assuming role: {SOURCE_ACCOUNT_ROLE_ARN}")

    # Role ARN에서 Account ID 추출: arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME
    acc_id = SOURCE_ACCOUNT_ROLE_ARN.split(":")[4]

    creds = sts_client.assume_role(
        RoleArn=SOURCE_ACCOUNT_ROLE_ARN,
        RoleSessionName="cwl-puller-source"
    )["Credentials"]
    logs_client = boto3.client(
        "logs",
        region_name=AWS_REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )

    s3_client = boto3.client("s3", region_name=AWS_REGION)
    return logs_client, s3_client, acc_id

logs_client = None
s3_client = None
account_id = None

# ===== 체크포인트 =====
class Checkpoint:
    """Lambda /tmp 기반 체크포인트"""
    def __init__(self, filepath: str = CHECKPOINT_FILE):
        self.filepath = filepath
        self.data = self._load()

    def _load(self) -> Dict[str, Any]:
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load checkpoint: {e}")
                return {}
        return {}

    def save(self):
        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.warning(f"Failed to save checkpoint: {e}")

    def get(self, log_group: str, log_stream: str) -> Optional[Dict[str, Any]]:
        return self.data.get(f"{log_group}::{log_stream}")

    def set(self, log_group: str, log_stream: str, checkpoint: Dict[str, Any]):
        self.data[f"{log_group}::{log_stream}"] = checkpoint
        self.save()

# ===== AWS API 호출 래퍼 =====
def describe_log_groups(next_token: Optional[str] = None) -> Dict[str, Any]:
    params = {}
    if next_token:
        params["nextToken"] = next_token
    return retry_call(logs_client.describe_log_groups, 5, 1, **params)

def describe_log_streams(log_group_name: str, next_token: Optional[str] = None) -> Dict[str, Any]:
    params = {
        "logGroupName": log_group_name,
        "orderBy": "LastEventTime",
        "descending": True
    }
    if next_token:
        params["nextToken"] = next_token
    return retry_call(logs_client.describe_log_streams, 5, 1, **params)

def get_log_events(log_group_name: str, log_stream_name: str,
                   start_time: Optional[int] = None, end_time: Optional[int] = None,
                   next_token: Optional[str] = None) -> Dict[str, Any]:
    params = {
        "logGroupName": log_group_name,
        "logStreamName": log_stream_name,
        "startFromHead": True
    }
    if start_time:
        params["startTime"] = start_time
    if end_time:
        params["endTime"] = end_time
    if next_token:
        params["nextToken"] = next_token
    return retry_call(logs_client.get_log_events, 5, 1, **params)

# ===== S3 업로드 =====
def upload_to_s3(data: List[Dict[str, Any]], log_group: str, log_stream: str, part_id: int) -> int:
    """로그 이벤트를 JSON.GZ 형식으로 S3에 업로드"""
    if not data:
        return 0

    # 로그 이벤트의 첫 번째 timestamp를 기준으로 날짜 추출 (밀리초 -> 초)
    # CloudWatch 로그 이벤트 형식: {"timestamp": 1697385600000, "message": "..."}
    first_event_timestamp = data[0].get("timestamp", int(time.time() * 1000))
    event_date = datetime.fromtimestamp(first_event_timestamp / 1000, tz=timezone.utc).strftime("%Y-%m-%d")

    # 파일명 생성: log_group + log_stream + part_id를 기반으로 고유한 파일명
    # 특수문자 제거 및 정리
    safe_group = log_group.replace("/", "_").replace(" ", "_")
    safe_stream = log_stream.replace("/", "_").replace(" ", "_").replace("[", "").replace("]", "")
    filename = f"{safe_group}_{safe_stream}_part{part_id}.json.gz"

    # 새로운 경로 구조: cloudwatch/dt=YYYY-MM-DD/account=ACCOUNT_ID/region=REGION/filename.json.gz
    s3_key = f"{PREFIX}/dt={event_date}/account={account_id}/region={AWS_REGION}/{filename}"

    json_content = json.dumps(data, ensure_ascii=False, indent=2)
    compressed = gzip.compress(json_content.encode("utf-8"))

    try:
        s3_client.put_object(
            Bucket=BUCKET,
            Key=s3_key,
            Body=compressed,
            ContentType="application/json",
            ContentEncoding="gzip",
            ServerSideEncryption="AES256",
        )
        return len(compressed)
    except ClientError as e:
        logger.error(f"✗ S3 upload failed for {s3_key}: {e}")
        raise

# ===== 처리 로직 =====
def process_log_stream(log_group: str, log_stream: str,
                       start_time: Optional[int], end_time: Optional[int],
                       checkpoint: Checkpoint, buffer_size: int = 50000) -> Dict[str, int]:
    """단일 로그 스트림 처리 (통계 반환)"""
    state = checkpoint.get(log_group, log_stream)
    if state and state.get("completed"):
        logger.info(f"Skipping completed stream: {log_group}/{log_stream}")
        return {"events": 0, "bytes": 0}

    next_token = state.get("nextToken") if state else None
    part_id = state.get("partId", 0) if state else 0
    buffer: List[Dict[str, Any]] = []
    total_events = 0
    total_bytes = 0

    prev_token = None
    while True:
        resp = get_log_events(log_group, log_stream, start_time, end_time, next_token)
        events = resp.get("events", [])
        forward_token = resp.get("nextForwardToken")

        # 더 이상 새로운 이벤트가 없으면 종료
        if not events and forward_token == next_token:
            break

        if events:
            total_events += len(events)
            buffer.extend(events)

            if len(buffer) >= buffer_size:
                uploaded_bytes = upload_to_s3(buffer, log_group, log_stream, part_id)
                total_bytes += uploaded_bytes
                part_id += 1
                buffer = []
                checkpoint.set(log_group, log_stream, {"nextToken": forward_token, "partId": part_id})

        # 토큰이 변경되지 않으면 종료 (페이지네이션 끝)
        if forward_token == prev_token or forward_token == next_token:
            break

        prev_token = next_token
        next_token = forward_token

    # 남은 버퍼 flush
    if buffer:
        uploaded_bytes = upload_to_s3(buffer, log_group, log_stream, part_id)
        total_bytes += uploaded_bytes
        part_id += 1

    checkpoint.set(log_group, log_stream, {"completed": True, "partId": part_id})

    if total_events > 0:
        logger.info(f"✓ Completed: {log_stream} ({total_events} events)")

    return {"events": total_events, "bytes": total_bytes}

def process_log_group(log_group: str, start_time: Optional[int], end_time: Optional[int], checkpoint: Checkpoint) -> Dict[str, int]:
    """단일 로그 그룹의 모든 스트림 처리 (통계 반환)"""
    logger.info(f"Processing log group: {log_group}")
    next_token = None
    total_streams = 0
    total_events = 0
    total_bytes = 0

    while True:
        try:
            resp = describe_log_streams(log_group, next_token)
            for s in resp.get("logStreams", []):
                stats = process_log_stream(log_group, s["logStreamName"], start_time, end_time, checkpoint)
                total_streams += 1
                total_events += stats["events"]
                total_bytes += stats["bytes"]

            next_token = resp.get("nextToken")
            if not next_token:
                break
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                logger.warning(f"Log group not found: {log_group}")
                break
            raise

    return {"streams": total_streams, "events": total_events, "bytes": total_bytes}

def run_pull(log_group_prefix: Optional[str], start_time_ms: Optional[int], end_time_ms: Optional[int]):
    """모든 로그 그룹 스캔 및 처리"""
    checkpoint = Checkpoint(CHECKPOINT_FILE)
    next_token = None
    processed_groups = 0
    total_streams = 0
    total_events = 0
    total_bytes = 0

    logger.info(f"Starting pull - prefix: {log_group_prefix}, time: {start_time_ms} ~ {end_time_ms}")

    while True:
        resp = describe_log_groups(next_token)
        for g in resp.get("logGroups", []):
            name = g["logGroupName"]
            if log_group_prefix and not name.startswith(log_group_prefix):
                continue

            stats = process_log_group(name, start_time_ms, end_time_ms, checkpoint)
            processed_groups += 1
            total_streams += stats["streams"]
            total_events += stats["events"]
            total_bytes += stats["bytes"]

        next_token = resp.get("nextToken")
        if not next_token:
            break

    # 통계 출력
    size_mb = total_bytes / (1024 * 1024)
    size_gb = total_bytes / (1024 * 1024 * 1024)

    if size_gb >= 1:
        size_str = f"{size_gb:.2f} GB"
    else:
        size_str = f"{size_mb:.2f} MB"

    logger.info(f"✓ Pull completed: {processed_groups} log groups, {total_streams} log streams, {total_events} events, {size_str} uploaded")

# ===== Lambda Handler =====
def lambda_handler(event, context):
    """Lambda 핸들러"""
    global logs_client, s3_client, account_id

    logger.info(f"Lambda invoked - Remaining time: {context.get_remaining_time_in_millis() / 1000:.1f}s")

    if not BUCKET:
        logger.error("BUCKET environment variable is required")
        raise RuntimeError("BUCKET env var is required.")

    payload = {}
    if "Records" in event and event["Records"] and "Sns" in event["Records"][0]:
        msg = event["Records"][0]["Sns"]["Message"]
        try:
            payload = json.loads(msg) if isinstance(msg, str) else {}
            logger.info(f"SNS payload: {json.dumps(payload, ensure_ascii=False)}")
        except Exception as e:
            logger.error(f"Failed to parse SNS message: {e}")
            return {"status": "error", "reason": "invalid SNS message"}
    else:
        payload = event if isinstance(event, dict) else {}
        logger.info(f"Direct invocation payload: {json.dumps(payload, ensure_ascii=False)}")

    start_sec = payload.get("start_time")
    end_sec = payload.get("end_time")
    log_group_prefix = payload.get("log_group_prefix")
    start_time = int(start_sec) * 1000 if start_sec else None
    end_time = int(end_sec) * 1000 if end_sec else None

    try:
        logs_client, s3_client, account_id = init_clients()
        run_pull(log_group_prefix, start_time, end_time)

        logger.info("✓ Lambda execution completed successfully")
        return {"status": "ok"}

    except Exception as e:
        logger.error(f"✗ Lambda execution failed: {e}", exc_info=True)
        return {"status": "error", "reason": str(e)}