
import os
import json
import gzip
import time
import random
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List
from urllib.parse import quote
import boto3
from botocore.exceptions import ClientError

# ===== 로깅 설정 =====
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ===== 환경변수 =====
AWS_REGION = os.getenv("AWS_REGION", "ap-northeast-2")
SOURCE_ACCOUNT_ROLE_ARN = os.getenv("SOURCE_ACCOUNT_ROLE_ARN")
BUCKET = os.getenv("BUCKET", "cirfrawtest")
PREFIX = os.getenv("PREFIX", "cwl-pull")
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

    if SOURCE_ACCOUNT_ROLE_ARN:
        logger.info(f"Assuming role: {SOURCE_ACCOUNT_ROLE_ARN}")
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
    else:
        logger.info("Using same-account credentials")
        logs_client = boto3.client("logs", region_name=AWS_REGION)

    s3_client = boto3.client("s3", region_name=AWS_REGION)
    return logs_client, s3_client

logs_client = None
s3_client = None

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
def upload_to_s3(data: List[Dict[str, Any]], log_group: str, log_stream: str, part_id: int):
    """로그 이벤트를 JSONL.GZ 형식으로 S3에 업로드"""
    if not data:
        return

    encoded_group = quote(log_group, safe="")
    encoded_stream = quote(log_stream, safe="")
    s3_key = f"{PREFIX}/region={AWS_REGION}/group={encoded_group}/stream={encoded_stream}/part-{part_id}.jsonl.gz"

    jsonl_content = "\n".join([json.dumps(e, ensure_ascii=False) for e in data])
    compressed = gzip.compress(jsonl_content.encode("utf-8"))

    try:
        s3_client.put_object(
            Bucket=BUCKET,
            Key=s3_key,
            Body=compressed,
            ContentType="application/gzip",
            ContentEncoding="gzip",
            ServerSideEncryption="AES256",
        )
        logger.info(f"✓ Uploaded s3://{BUCKET}/{s3_key} ({len(data)} events, {len(compressed)} bytes)")
    except ClientError as e:
        logger.error(f"✗ S3 upload failed for {s3_key}: {e}")
        raise

# ===== 처리 로직 =====
def process_log_stream(log_group: str, log_stream: str,
                       start_time: Optional[int], end_time: Optional[int],
                       checkpoint: Checkpoint, buffer_size: int = 10000):
    """단일 로그 스트림 처리 (디버깅 로그 포함)"""
    state = checkpoint.get(log_group, log_stream)
    if state and state.get("completed"):
        logger.info(f"Skipping completed stream: {log_group}/{log_stream}")
        return

    next_token = state.get("nextToken") if state else None
    part_id = state.get("partId", 0) if state else 0
    buffer: List[Dict[str, Any]] = []
    total_events = 0

    logger.info(f"Processing stream: {log_group}/{log_stream}")
    logger.info(f"Time range: {start_time} ~ {end_time}")

    while True:
        resp = get_log_events(log_group, log_stream, start_time, end_time, next_token)
        events = resp.get("events", [])
        forward_token = resp.get("nextForwardToken")
        
        total_events += len(events)
        logger.info(f"Fetched {len(events)} events (total: {total_events})")

        if events:
            buffer.extend(events)
            if len(buffer) >= buffer_size:
                upload_to_s3(buffer, log_group, log_stream, part_id)
                part_id += 1
                buffer = []
                checkpoint.set(log_group, log_stream, {"nextToken": forward_token, "partId": part_id})

        if forward_token == next_token:
            break
        next_token = forward_token

    # 남은 버퍼 flush
    if buffer:
        logger.info(f"Flushing remaining {len(buffer)} events")
        upload_to_s3(buffer, log_group, log_stream, part_id)
        part_id += 1
    else:
        logger.warning(f"No events to upload for {log_group}/{log_stream}")

    checkpoint.set(log_group, log_stream, {"completed": True, "partId": part_id})
    logger.info(f"✓ Completed stream: {log_group}/{log_stream} ({part_id} parts, {total_events} total events)")

def process_log_group(log_group: str, start_time: Optional[int], end_time: Optional[int], checkpoint: Checkpoint):
    """단일 로그 그룹의 모든 스트림 처리"""
    logger.info(f"Processing log group: {log_group}")
    next_token = None

    while True:
        try:
            resp = describe_log_streams(log_group, next_token)
            for s in resp.get("logStreams", []):
                process_log_stream(log_group, s["logStreamName"], start_time, end_time, checkpoint)

            next_token = resp.get("nextToken")
            if not next_token:
                break
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                logger.warning(f"Log group not found: {log_group}")
                break
            raise

def run_pull(log_group_prefix: Optional[str], start_time_ms: Optional[int], end_time_ms: Optional[int]):
    """모든 로그 그룹 스캔 및 처리"""
    checkpoint = Checkpoint(CHECKPOINT_FILE)
    next_token = None
    processed_groups = 0

    logger.info(f"Starting pull - prefix: {log_group_prefix}, time: {start_time_ms} ~ {end_time_ms}")

    while True:
        resp = describe_log_groups(next_token)
        for g in resp.get("logGroups", []):
            name = g["logGroupName"]
            if log_group_prefix and not name.startswith(log_group_prefix):
                continue

            process_log_group(name, start_time_ms, end_time_ms, checkpoint)
            processed_groups += 1

        next_token = resp.get("nextToken")
        if not next_token:
            break

    logger.info(f"✓ Pull completed: {processed_groups} log groups processed")

# ===== 필터 헬퍼 =====
def _has_cloudwatch_dest(event: dict, payload: dict) -> bool:
    """SNS MessageAttributes 또는 payload에서 logDestType=cloudwatch 확인"""
    try:
        if "Records" in event and event["Records"] and "Sns" in event["Records"][0]:
            attrs = event["Records"][0]["Sns"].get("MessageAttributes", {}) or {}
            if "logDestType" in attrs:
                attr = attrs["logDestType"]
                if attr.get("Type") == "String.Array":
                    arr = json.loads(attr.get("Value") or "[]")
                    return any(str(v).lower() == "cloudwatch" for v in arr)
                if attr.get("Type") == "String":
                    return str(attr.get("Value", "")).lower() == "cloudwatch"
    except Exception as e:
        logger.warning(f"Failed to parse MessageAttributes: {e}")

    vals = payload.get("logDestType")
    if isinstance(vals, list):
        return any(str(v).lower() == "cloudwatch" for v in vals)
    if isinstance(vals, str):
        return vals.lower() == "cloudwatch"

    return False

# ===== Lambda Handler =====
def lambda_handler(event, context):
    """Lambda 핸들러"""
    global logs_client, s3_client

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

    if not _has_cloudwatch_dest(event, payload):
        logger.info("Skipping: logDestType != cloudwatch")
        return {"status": "skipped", "reason": "logDestType != cloudwatch"}

    start_sec = payload.get("start_time")
    end_sec = payload.get("end_time")
    log_group_prefix = payload.get("log_group_prefix")
    start_time = int(start_sec) * 1000 if start_sec else None
    end_time = int(end_sec) * 1000 if end_sec else None

    try:
        logs_client, s3_client = init_clients()
        run_pull(log_group_prefix, start_time, end_time)

        logger.info("✓ Lambda execution completed successfully")
        return {"status": "ok"}

    except Exception as e:
        logger.error(f"✗ Lambda execution failed: {e}", exc_info=True)
        return {"status": "error", "reason": str(e)}