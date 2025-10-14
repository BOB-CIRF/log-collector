import json
import boto3
from botocore.config import Config
import logging
import os
from datetime import datetime
from dynamodb_repostiory import DynamoDBRepository

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def save_regional_scan_results(scan_id, logs, account_id):
    """
    리전별 스캔 결과를 DynamoDB에 저장

    Args:
        scan_id: 스캔 ID
        logs: 스캔된 로그 목록 (destination 정보 포함)
        account_id: AWS 계정 ID
    """
    if not logs:
        logger.info(f"No logs to save for scan_id {scan_id}")
        return

    repo = DynamoDBRepository()

    try:
        total_destinations = 0

        # 각 로그를 DynamoDB에 저장
        for log in logs:
            # Atomic Counter로 log_id 생성
            log_id = repo.get_next_log_id()

            # scan_log 생성
            scan_log = repo.create_scan_log(
                scan_id=scan_id,
                log_id=log_id,
                log_type=log.get('log_type'),
                log_arn=log.get('log_arn'),
                log_region=log.get('log_region'),
                account_id=account_id
            )

            logger.debug(f"Created scan log: {log_id} for scan {scan_id}")

            # destination 정보 저장
            destinations = log.get('destination', [])
            if destinations:
                for dest in destinations:
                    # Atomic Counter로 dest_id 생성
                    dest_id = repo.get_next_dest_id()

                    repo.create_scan_log_destination(
                        scan_id=scan_id,
                        log_id=log_id,
                        dest_id=dest_id,
                        dest_type=dest.get('destination_type', 'UNKNOWN'),
                        dest_arn=dest.get('destination_arn', ''),
                        dest_region=dest.get('destination_region', '')
                    )

                    total_destinations += 1
                    logger.debug(f"Created destination: {dest_id} for log {log_id}")

        logger.info(f"Saved {len(logs)} logs and {total_destinations} destinations for scan_id {scan_id}")

    except Exception as e:
        logger.error(f"DB 저장 오류 (scan_id={scan_id}): {str(e)}")
        raise


