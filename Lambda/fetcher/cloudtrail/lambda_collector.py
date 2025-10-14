import json
import os
import boto3
from datetime import datetime
from typing import Dict, Any, List, Optional
import logging

# 로깅 설정
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# 환경변수
S3_BUCKET_NAME = os.environ['S3_BUCKET_NAME']
S3_PREFIX = os.environ.get('S3_PREFIX', 'cloudtrail-logs')
TARGET_ACCOUNT_ROLE_ARN = os.environ.get('TARGET_ACCOUNT_ROLE_ARN')  # Cross Account Role ARN (선택)

# AWS 클라이언트 초기화
def get_cloudtrail_client() -> Any:
    """
    CloudTrail 클라이언트를 생성 (Cross Account 지원)

    Returns:
        CloudTrail 클라이언트 (STS assume role 사용 시 cross account 접근)
    """
    if TARGET_ACCOUNT_ROLE_ARN:
        # Cross Account 접근을 위한 STS assume role
        logger.info(f"Assuming role for cross-account access: {TARGET_ACCOUNT_ROLE_ARN}")
        sts = boto3.client('sts')

        assumed_role = sts.assume_role(
            RoleArn=TARGET_ACCOUNT_ROLE_ARN,
            RoleSessionName='cloudtrail-collector-session'
        )

        credentials = assumed_role['Credentials']

        return boto3.client(
            'cloudtrail',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
    else:
        # 동일 계정 접근
        logger.info("Using same-account CloudTrail access")
        return boto3.client('cloudtrail')


# S3 클라이언트 (동일 계정)
s3 = boto3.client('s3')


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    SQS 메시지를 받아 CloudTrail 이벤트를 조회하고 S3에 저장하는 Lambda 함수

    Args:
        event: SQS 이벤트
        context: Lambda 실행 컨텍스트

    Returns:
        실행 결과 딕셔너리
    """
    total_events = 0
    failed_events = 0

    try:
        # SQS 메시지 처리 (배치 처리 가능)
        for record in event['Records']:
            try:
                # SQS 메시지 파싱
                message = json.loads(record['body'])
                start_time_str = message['start_time']
                end_time_str = message['end_time']

                logger.info(f"Processing time range: {start_time_str} to {end_time_str}")

                # ISO 8601 형식의 시간 문자열을 datetime으로 변환
                start_time = parse_datetime(start_time_str)
                end_time = parse_datetime(end_time_str)

                # CloudTrail 클라이언트 생성 (Cross Account 지원)
                cloudtrail_client = get_cloudtrail_client()

                # CloudTrail 이벤트 조회
                events = fetch_cloudtrail_events(cloudtrail_client, start_time, end_time)

                logger.info(f"Fetched {len(events)} events for time range")

                # S3에 이벤트 저장
                saved = save_events_to_s3(events)
                total_events += saved

            except Exception as e:
                logger.error(f"Error processing SQS record: {str(e)}")
                failed_events += 1
                # 개별 메시지 처리 실패 시 계속 진행 (다른 메시지는 처리)
                continue

        result = {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'CloudTrail events processed successfully',
                'total_events_saved': total_events,
                'failed_records': failed_events
            })
        }

        logger.info(f"Processing complete - Events saved: {total_events}, Failed records: {failed_events}")
        return result

    except Exception as e:
        logger.error(f"Unexpected error in lambda_handler: {str(e)}")
        raise


def parse_datetime(datetime_str: str) -> datetime:
    """
    ISO 8601 형식의 시간 문자열을 datetime 객체로 변환

    Args:
        datetime_str: ISO 8601 형식의 시간 문자열 (예: 2025-10-09T00:00:00+09:00)

    Returns:
        datetime 객체
    """
    # Python 3.11+ 에서는 fromisoformat이 타임존을 완전히 지원
    try:
        return datetime.fromisoformat(datetime_str.replace('Z', '+00:00'))
    except ValueError:
        # 대체 파싱 방법
        return datetime.strptime(datetime_str.replace('+09:00', ''), '%Y-%m-%dT%H:%M:%S')


def fetch_cloudtrail_events(cloudtrail_client: Any, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
    """
    CloudTrail API를 사용하여 지정된 시간 범위의 이벤트를 조회

    Args:
        cloudtrail_client: CloudTrail 클라이언트 (Cross Account 지원)
        start_time: 조회 시작 시간
        end_time: 조회 종료 시간

    Returns:
        CloudTrail 이벤트 리스트
    """
    events = []
    next_token = None

    try:
        while True:
            # CloudTrail lookup_events API 호출
            params = {
                'StartTime': start_time,
                'EndTime': end_time,
                'MaxResults': 50  # API 최대값
            }

            if next_token:
                params['NextToken'] = next_token

            response = cloudtrail_client.lookup_events(**params)

            # 이벤트 수집
            events.extend(response.get('Events', []))

            # Pagination 처리
            next_token = response.get('NextToken')
            if not next_token:
                break

            logger.info(f"Fetched {len(events)} events so far, continuing pagination...")

    except Exception as e:
        logger.error(f"Error fetching CloudTrail events: {str(e)}")
        raise

    return events


def save_events_to_s3(events: List[Dict[str, Any]]) -> int:
    """
    CloudTrail 이벤트를 S3에 개별 파일로 저장

    Args:
        events: CloudTrail 이벤트 리스트

    Returns:
        저장된 이벤트 수
    """
    saved_count = 0

    for event in events:
        try:
            # 이벤트 메타데이터 추출
            event_id = event.get('EventId')
            event_time = event.get('EventTime')

            if not event_id or not event_time:
                logger.warning(f"Event missing required fields, skipping: {event}")
                continue

            # S3 키 생성: cloudtrail-logs/YYYY/MM/DD/{event_id}.json
            year = event_time.strftime('%Y')
            month = event_time.strftime('%m')
            day = event_time.strftime('%d')

            s3_key = f"{S3_PREFIX}/{year}/{month}/{day}/{event_id}.json"

            # 이벤트를 JSON으로 변환
            event_json = json.dumps(event, default=str, ensure_ascii=False, indent=2)

            # S3에 업로드
            s3.put_object(
                Bucket=S3_BUCKET_NAME,
                Key=s3_key,
                Body=event_json,
                ContentType='application/json'
            )

            saved_count += 1

            if saved_count % 10 == 0:
                logger.info(f"Saved {saved_count} events to S3...")

        except Exception as e:
            logger.error(f"Error saving event {event.get('EventId', 'unknown')} to S3: {str(e)}")
            # 개별 이벤트 저장 실패 시 계속 진행
            continue

    logger.info(f"Successfully saved {saved_count} events to S3")
    return saved_count
