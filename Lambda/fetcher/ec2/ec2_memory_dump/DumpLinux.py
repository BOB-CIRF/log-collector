# DumpLinux.py
# Runtime: Python 3.11

import os
import time
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone

def _get_credentials(target_role_arn: str = None):
    """교차 계정 Role ARN이 제공되면 AssumeRole 수행"""
    if not target_role_arn:
        return {}

    sts = boto3.client("sts")
    try:
        assumed = sts.assume_role(
            RoleArn=target_role_arn,
            RoleSessionName="DumpLinuxSession"
        )
        creds = assumed["Credentials"]
        return {
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"]
        }
    except ClientError as e:
        print(f"[WARN] AssumeRole failed: {e}")
        return {}

LINUX_COMMANDS = [
    "#!/bin/bash",
    "set -e",  
    "",
    "# 0) avml 준비 (ssm-user 홈 디렉토리 사용)",
    "cd ~",
    "curl -fsSL -o avml https://github.com/microsoft/avml/releases/latest/download/avml 2>&1 || {",
    "  echo '[ERROR] Failed to download avml'",
    "  exit 1",
    "}",
    "chmod +x avml",
    "",
    "# 1) 고유 경로(인스턴스ID + UTC)",
    "BASE=/forensics",
    "TOKEN=$(curl -fsS -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds:21600' 2>/dev/null || echo '')",
    "if [ -n \"$TOKEN\" ]; then",
    "  IID=$(curl -fsS -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || hostname)",
    "else",
    "  IID=$(hostname)",
    "fi",
    "TS=$(date -u +%Y%m%dT%H%M%SZ)",
    "OUT=\"$BASE/$IID/$TS\"",
    "sudo mkdir -p \"$OUT\" || {",
    "  echo '[ERROR] Failed to create output directory'",
    "  exit 1",
    "}",
    "",
    "# 2) 공간 체크 (RAM + 100MB)",
    "MEM=$(awk '/MemTotal/ {print $2*1024}' /proc/meminfo)",
    "NEEDED=$((MEM + 100*1024*1024))",
    "AVAIL=$(df -P \"$BASE\" | awk 'NR==2{print $4*1024}')",
    "if [ \"$AVAIL\" -lt \"$NEEDED\" ]; then",
    "  echo \"[ERROR] Not enough space. Need: $NEEDED bytes, Available: $AVAIL bytes\"",
    "  exit 1",
    "fi",
    "",
    "# 3) 덤프 실행",
    "DUMP=\"$OUT/memdump.avml\"",
    "echo \"[INFO] Starting memory dump to $DUMP\"",
    "sudo ~/avml \"$DUMP\" || {",
    "  echo '[ERROR] Memory dump failed'",
    "  exit 1",
    "}",
    "",
    "# 4) 해시 및 메타데이터 생성",
    "sudo chmod 640 \"$DUMP\"",
    "sudo sha256sum \"$DUMP\" | sudo tee \"$DUMP.sha256\" >/dev/null",
    "sudo md5sum \"$DUMP\" | sudo tee \"$DUMP.md5\" >/dev/null",
    "",
    "# 5) 메타데이터 JSON 생성",
    "sudo bash -c \"cat > $OUT/metadata.json\" <<EOF",
    "{",
    "  \\\"instance_id\\\": \\\"${IID}\\\",",
    "  \\\"utc_time\\\": \\\"${TS}\\\",",
    "  \\\"kernel\\\": \\\"$(uname -srmo)\\\",",
    "  \\\"size_bytes\\\": $(sudo stat -c%s \\\"$DUMP\\\"),",
    "  \\\"sha256\\\": \\\"$(sudo cut -d' ' -f1 \\\"$DUMP.sha256\\\")\\\"",
    "}",
    "EOF",
    "",
    "sudo chmod 644 \"$DUMP.sha256\" \"$DUMP.md5\" \"$OUT/metadata.json\"",
    "sudo sync",
    "echo \"Saved to $OUT\"",
    "echo \"[SUCCESS] Memory dump completed successfully\""
]

def lambda_handler(event, context):
    """
    event:
      instanceId (str, required)
      region (str, optional)
      incident_id (str, optional)
      targetRoleArn (str, optional)  
      dumpDir (str, optional) 
    """
    instance_id = event["instanceId"]
    region = event.get("region") or os.environ.get("AWS_REGION", "ap-northeast-2")
    incident_id = event.get("incident_id")
    target_role_arn = event.get("targetRoleArn") 

 
    creds = _get_credentials(target_role_arn)

    ssm = boto3.client("ssm", region_name=region, **creds)

    try:
        resp = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": LINUX_COMMANDS},
            Comment=f"Memory dump via AVML (incident={incident_id})" if incident_id else "Memory dump via AVML",
            CloudWatchOutputConfig={"CloudWatchOutputEnabled": True},
            TimeoutSeconds=3600,
        )
    except ClientError as e:
        raise

    cmd = resp["Command"]
    command_id = cmd["CommandId"]

    # 동기 방식: 명령 완료까지 대기 (최대 1시간)
    max_wait_time = 3600  # 1시간
    poll_interval = 10  # 10초마다 확인
    elapsed_time = 0

    while elapsed_time < max_wait_time:
        time.sleep(poll_interval)
        elapsed_time += poll_interval

        try:
            invocation = ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )

            status = invocation["Status"]

            if status == "Success":
                # 출력에서 실제 덤프 경로 추출
                output = invocation.get("StandardOutputContent", "")
                dump_path = "/forensics/<INSTANCE_ID>/<TIMESTAMP>/memdump.avml"

                # "Saved to" 라인에서 경로 추출 시도
                for line in output.split("\n"):
                    if "Saved to" in line:
                        dump_path = line.replace("Saved to", "").strip()
                        break

                return {
                    "instanceId": instance_id,
                    "region": region,
                    "os": "linux",
                    "document": "AWS-RunShellScript",
                    "commandId": command_id,
                    "status": "SUCCESS",
                    "dumpLocation": dump_path,
                    "completedAt": datetime.now(timezone.utc).isoformat(),
                    "executionTime": f"{elapsed_time}s",
                    "message": "Memory dump completed successfully",
                    "output": output[-500:] if len(output) > 500 else output  # 마지막 500자
                }

            elif status in ["Cancelled", "TimedOut", "Failed"]:
                error_output = invocation.get("StandardErrorContent", "No error details")
                raise Exception(f"SSM Command {status}: {error_output}")

            # InProgress, Pending 등은 계속 대기

        except ClientError as e:
            if e.response["Error"]["Code"] == "InvocationDoesNotExist":
                # 아직 invocation이 생성되지 않음, 계속 대기
                continue
            else:
                raise

    # 타임아웃
    raise Exception(f"Memory dump command timed out after {max_wait_time}s")
