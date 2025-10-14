# DumpWindows.py
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
            RoleSessionName="DumpWindowsSession"
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

# 네가 준 PowerShell 명령을 그대로 사용
WINDOWS_COMMANDS = [
    "# 준비",
    "New-Item -ItemType Directory -Force -Path C:\\forensics | Out-Null",
    "cd C:\\forensics",
    "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12",
    "Invoke-WebRequest -Uri 'https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/go-winpmem_amd64_1.0-rc2_signed.exe' -OutFile 'go-winpmem_amd64_1.0-rc2_signed.exe'",
    "",
    "# 고유 경로: C:\\forensics\\<HOST>\\<UTC>_<GUID>\\",
    "$Base   = 'C:\\forensics'",
    "$HostId = $env:COMPUTERNAME",
    "$Now    = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')",
    "$Guid   = [guid]::NewGuid().ToString('N')",
    "$OutTop = Join-Path -Path $Base -ChildPath $HostId",
    "$Out    = Join-Path -Path $OutTop -ChildPath \"$Now`_$Guid\"",
    "New-Item -ItemType Directory -Path $Out -Force | Out-Null",
    "",
    "# 덤프",
    "$Dump = Join-Path -Path $Out -ChildPath 'mem.raw'",
    ".\\go-winpmem_amd64_1.0-rc2_signed.exe acquire $Dump",
    "",
    "# 해시 저장",
    "(Get-FileHash -Algorithm SHA256 $Dump).Hash | Set-Content (Join-Path $Out 'mem.raw.sha256.txt')",
    "(Get-FileHash -Algorithm MD5 $Dump).Hash | Set-Content (Join-Path $Out 'mem.raw.md5.txt')",
    "Write-Host \"Saved to $Out\""
]

def lambda_handler(event, context):
    """
    event:
      instanceId (str, required)
      region (str, optional)
      incident_id (str, optional)
      targetRoleArn (str, optional)  # 교차 계정 Role ARN
      dumpDir (str, optional)  # 현재 스크립트는 C:\forensics 고정 사용
    """
    instance_id = event["instanceId"]
    region = event.get("region") or os.environ.get("AWS_REGION", "ap-northeast-2")
    incident_id = event.get("incident_id")
    target_role_arn = event.get("targetRoleArn")  # 교차 계정 Role ARN

    # 교차 계정 자격 증명 획득
    creds = _get_credentials(target_role_arn)

    ssm = boto3.client("ssm", region_name=region, **creds)

    try:
        resp = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunPowerShellScript",
            Parameters={"commands": WINDOWS_COMMANDS},
            Comment=f"Memory dump via WinPmem (incident={incident_id})" if incident_id else "Memory dump via WinPmem",
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
                dump_path = "C:\\forensics\\<COMPUTERNAME>\\<TIMESTAMP>_<GUID>\\mem.raw"

                # "Saved to" 라인에서 경로 추출 시도
                for line in output.split("\n"):
                    if "Saved to" in line:
                        dump_path = line.replace("Saved to", "").strip()
                        break

                return {
                    "instanceId": instance_id,
                    "region": region,
                    "os": "windows",
                    "document": "AWS-RunPowerShellScript",
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
