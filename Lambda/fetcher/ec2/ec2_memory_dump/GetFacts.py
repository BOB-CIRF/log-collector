# GetFacts.py
# Runtime: Python 3.11

import os
import boto3
from botocore.exceptions import ClientError

def _get_credentials(target_role_arn: str = None):
    """교차 계정 Role ARN이 제공되면 AssumeRole 수행"""
    if not target_role_arn:
        return {}

    sts = boto3.client("sts")
    try:
        assumed = sts.assume_role(
            RoleArn=target_role_arn,
            RoleSessionName="GetFactsSession"
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

def _infer_os_from_ec2(ec2_client, instance_id: str) -> str | None:
    """EC2 메타데이터로 OS 추론 (windows / linux)"""
    resp = ec2_client.describe_instances(InstanceIds=[instance_id])
    inst = resp["Reservations"][0]["Instances"][0]

    # 1) 'Platform' 필드가 'windows'면 확정
    if inst.get("Platform") == "windows":
        return "windows"

    # 2) PlatformDetails 문자열로 힌트
    pd = inst.get("PlatformDetails") or ""
    if "Windows" in pd:
        return "windows"

    # 대부분의 경우 비-Windows는 Linux 취급
    return "linux"

def lambda_handler(event, context):
    instance_id = event["instanceId"]
    region = event.get("region") or os.environ.get("AWS_REGION", "ap-northeast-2")
    target_role_arn = event.get("targetRoleArn")  # 교차 계정 Role ARN

    # 교차 계정 자격 증명 획득
    creds = _get_credentials(target_role_arn)

    ssm = boto3.client("ssm", region_name=region, **creds)
    ec2 = boto3.client("ec2", region_name=region, **creds)

    ssm_managed = False
    os_type = None

    # 1) SSM에 등록되어 있는지, PlatformType으로 OS 파악 시도
    try:
        page = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        info = page.get("InstanceInformationList", [])
        if info:
            ssm_managed = True
            pt = info[0].get("PlatformType")  # 'Windows' or 'Linux'
            if pt:
                os_type = pt.lower()
    except ClientError:
        # 권한/지역/인스턴스 상태 문제 시에도 EC2로 OS 추론 시도
        pass

    # 2) OS 미정이면 EC2 API로 보조 판별
    if not os_type:
        try:
            os_type = _infer_os_from_ec2(ec2, instance_id)
        except ClientError:
            os_type = None  # 마지막까지 모르겠으면 None

    return {
        "instanceId": instance_id,
        "region": region,
        "ssmManaged": ssm_managed,
        "os": os_type,
    }
