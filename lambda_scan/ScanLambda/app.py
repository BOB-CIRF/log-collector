import json
import boto3
from botocore.config import Config
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import _assume
from crud import save_regional_scan_results
from scan import scan_cloudtrail, scan_s3_logging, scan_vpc_flow_logs, scan_api_gateway, scan_elb_logs, scan_config, scan_rds_audit_logs, scan_redshift_audit_logs, scan_fsx_audit_logs, scan_client_vpn_logs, scan_workspaces_logs, scan_route53_resolver_logs, scan_wafv2, scan_eks_logs, scan_network_firewall_logs, scan_transit_gateway_flow_logs, scan_cloudfront, scan_session_manager_logs, scan_wafv2_global, scan_global_accelerator

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 최대 동시 실행 워커 수
MAX_WORKERS = 20

def _scan_service(scan_func, service_name, sess, region, account_id, *args):
    """개별 서비스 스캔을 실행하는 헬퍼 함수"""
    try:
        logger.info(f"  [{region}] Scanning {service_name}...")
        results = scan_func(sess, *args)
        logger.info(f"  [{region}] {service_name}: {len(results)} items")
        return results
    except Exception as e:
        logger.error(f"  [{region}] Error scanning {service_name}: {str(e)}")
        return []

def scan_region(sess, region, account_id):
    """단일 리전 스캔 - 비동기 병렬 실행"""
    logger.info(f"Starting parallel scan for region: {region}")

    # 스캔할 서비스 목록 정의
    scan_tasks = [
        # 모든 리전에서 실행
        (scan_cloudtrail, "CloudTrail", region, account_id),
        (scan_vpc_flow_logs, "VPC Flow Logs", region, account_id),
        (scan_api_gateway, "API Gateway", region, account_id),
        (scan_elb_logs, "ELB", region, account_id),
        (scan_config, "Config", region, account_id),
        (scan_rds_audit_logs, "RDS/Aurora Audit Logs", region, account_id),
        (scan_redshift_audit_logs, "Redshift Audit Logs", region, account_id),
        (scan_fsx_audit_logs, "FSx Audit Logs", region, account_id),
        (scan_client_vpn_logs, "Client VPN Logs", region, account_id),
        (scan_workspaces_logs, "WorkSpaces Logs", region, account_id),
        (scan_route53_resolver_logs, "Route53 Resolver", region, account_id),
        (scan_wafv2, "WAFv2", region, account_id),
        (scan_eks_logs, "EKS", region, account_id),
        (scan_network_firewall_logs, "Network Firewall Logs", region, account_id),
        (scan_transit_gateway_flow_logs, "Transit Gateway Flow Logs", region, account_id),
        (scan_session_manager_logs, "Session Manager Logs", region, account_id),
    ]

    # us-east-1 전용 글로벌 서비스
    if region == "us-east-1":
        scan_tasks.extend([
            (scan_s3_logging, "S3 Access Logs", account_id),
            (scan_cloudfront, "CloudFront", account_id),
            (scan_wafv2_global, "WAFv2 Global", account_id),
        ])

    # us-west-2 전용 글로벌 서비스
    if region == "us-west-2":
        scan_tasks.append(
            (scan_global_accelerator, "Global Accelerator", account_id)
        )

    # ThreadPoolExecutor로 병렬 실행
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 모든 스캔 작업 제출
        futures = {
            executor.submit(_scan_service, scan_func, service_name, sess, region, account_id, *args): service_name
            for scan_func, service_name, *args in scan_tasks
        }

        # 완료되는 대로 결과 수집
        for future in as_completed(futures):
            service_name = futures[future]
            try:
                service_results = future.result()
                results.extend(service_results)
            except Exception as e:
                logger.error(f"  [{region}] Unexpected error in {service_name}: {str(e)}")

    logger.info(f"Completed parallel scan for region {region}: {len(results)} total items")
    return results

def lambda_handler(event, context):
    try:
        # Step Functions에서 전달받은 파라미터
        scan_id = event.get('scan_id')
        account_id = event.get('account_id')
        region = event.get('region')
        role_arn = event.get('role_arn')
        external_id = event.get('external_id')

        if not all([scan_id, account_id, region, role_arn]):
            raise ValueError("scan_id, account_id, region, role_arn are required")

        logger.info(f"Starting scan for account {account_id}, region {region}, scan_id {scan_id}")

        # AWS 세션 설정
        base = boto3.Session()
        sess = _assume(base, role_arn, external_id)

        # 단일 리전만 스캔 (Step Functions의 Map state가 리전별로 병렬 실행)
        regional_results = scan_region(sess, region, account_id)

        # DB에 저장 (기존 scan_id 사용)
        save_regional_scan_results(scan_id, regional_results, account_id)

        logger.info(f"Completed scan for region {region}: {len(regional_results)} items saved")

        # Step Functions 응답
        return {
            'scan_id': scan_id,
            'region': region,
            'items_count': len(regional_results),
            'status': 'SUCCESS'
        }

    except Exception as e:
        logger.error(f"Handler error for region {region}: {str(e)}")
        # Step Functions에 에러 전파
        raise