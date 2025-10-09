
import json
import os
import boto3
from datetime import datetime, timedelta
from typing import Dict, Any, List
import logging

# 로깅 설정
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# SQS 클라이언트 초기화
sqs = boto3.client('sqs')

# 환경변수
SQS_QUEUE_URL = os.environ['SQS_QUEUE_URL']


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    SNS 메시지를 받아 1시간 단위로 시간 범위를 분할하여 SQS로 전송하는 Lambda 함수

    Args:
        event: SNS 이벤트
        context: Lambda 실행 컨텍스트

    Returns:
        실행 결과 딕셔너리
    """
    try:
        # SNS 메시지 파싱
        sns_message = json.loads(event['Records'][0]['Sns']['Message'])
        start_date = sns_message['start_date']
        end_date = sns_message['end_date']

        logger.info(f"Processing date range: {start_date} to {end_date}")

        # 날짜 문자열을 KST datetime으로 변환
        start_dt = datetime.strptime(start_date, '%Y-%m-%d')
        end_dt = datetime.strptime(end_date, '%Y-%m-%d')

        # 시간 범위 검증
        if start_dt > end_dt:
            raise ValueError(f"start_date ({start_date}) must be before or equal to end_date ({end_date})")

        # 1시간 단위로 시간 범위 생성
        time_ranges = generate_hourly_ranges(start_dt, end_dt)

        logger.info(f"Generated {len(time_ranges)} hourly time ranges")

        # SQS로 메시지 전송
        send_to_sqs(time_ranges)

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Successfully split date range and sent to SQS',
                'total_ranges': len(time_ranges),
                'start_date': start_date,
                'end_date': end_date
            })
        }

    except KeyError as e:
        logger.error(f"Missing required field in event: {str(e)}")
        raise
    except ValueError as e:
        logger.error(f"Invalid date format or range: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise


def generate_hourly_ranges(start_dt: datetime, end_dt: datetime) -> List[Dict[str, str]]:
    """
    시작 날짜부터 종료 날짜까지 1시간 단위로 시간 범위를 생성

    Args:
        start_dt: 시작 날짜 (datetime)
        end_dt: 종료 날짜 (datetime)

    Returns:
        시간 범위 리스트 (각 항목은 start_time, end_time을 포함한 딕셔너리)
    """
    time_ranges = []
    current_time = start_dt

    # 종료일의 마지막 시간 (23:59:59)까지 처리
    end_time_limit = end_dt + timedelta(days=1)

    while current_time < end_time_limit:
        range_start = current_time
        range_end = current_time + timedelta(hours=1)

        # 마지막 범위가 종료일을 넘지 않도록 조정
        if range_end > end_time_limit:
            range_end = end_time_limit

        time_ranges.append({
            'start_time': range_start.strftime('%Y-%m-%dT%H:%M:%S+09:00'),  # KST 시간대 명시
            'end_time': range_end.strftime('%Y-%m-%dT%H:%M:%S+09:00')
        })

        current_time = range_end

    return time_ranges


def send_to_sqs(time_ranges: List[Dict[str, str]]) -> None:
    """
    시간 범위 리스트를 SQS로 전송 (배치 처리)

    Args:
        time_ranges: 시간 범위 리스트
    """
    # SQS 배치 전송 (최대 10개씩)
    batch_size = 10
    success_count = 0
    failed_count = 0

    for i in range(0, len(time_ranges), batch_size):
        batch = time_ranges[i:i + batch_size]
        entries = [
            {
                'Id': str(idx),
                'MessageBody': json.dumps(time_range)
            }
            for idx, time_range in enumerate(batch)
        ]

        try:
            response = sqs.send_message_batch(
                QueueUrl=SQS_QUEUE_URL,
                Entries=entries
            )

            success_count += len(response.get('Successful', []))
            failed_count += len(response.get('Failed', []))

            if response.get('Failed'):
                logger.warning(f"Failed to send some messages: {response['Failed']}")

        except Exception as e:
            logger.error(f"Error sending batch to SQS: {str(e)}")
            failed_count += len(entries)
            raise

    logger.info(f"SQS send complete - Success: {success_count}, Failed: {failed_count}")

    if failed_count > 0:
        raise Exception(f"Failed to send {failed_count} messages to SQS")
