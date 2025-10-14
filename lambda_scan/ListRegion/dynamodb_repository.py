import boto3
import os
from datetime import datetime
from decimal import Decimal
from typing import Optional, Dict, Any


class DynamoDBRepository:
    """DynamoDB 데이터 접근 계층"""

    def __init__(self, table_name: str = None):
        self.dynamodb = boto3.resource('dynamodb')
        self.table_name = table_name or os.environ.get('DYNAMODB_TABLE_NAME', 'cirf')
        self.table = self.dynamodb.Table(self.table_name)

    def get_next_scan_id(self) -> int:
        """Atomic Counter로 다음 scan_id 생성"""
        response = self.table.update_item(
            Key={
                'PK': 'COUNTER',
                'SK': 'SCAN_ID'
            },
            UpdateExpression='ADD #counter :inc',
            ExpressionAttributeNames={
                '#counter': 'counter'
            },
            ExpressionAttributeValues={
                ':inc': 1
            },
            ReturnValues='UPDATED_NEW'
        )
        return int(response['Attributes']['counter'])

    def get_account(self, tenant_id: str, case_id: str, account_id: str) -> Optional[Dict[str, Any]]:
        pk = f"TENANT#{tenant_id}#CASE#{case_id}"
        sk = f"ACCOUNT#{account_id}"

        response = self.table.get_item(
            Key={
                'PK': pk,
                'SK': sk
            }
        )

        return response.get('Item')

    def create_scan_metadata(
        self,
        scan_id: int,
        tenant_id: str,
        case_id: str,
        account_id: str,
        started_at: str,
        status: str = 'RUNNING'
    ) -> Dict[str, Any]:
        scan_metadata = {
            'PK': f"SCAN#{scan_id}",
            'SK': 'METADATA',
            'scan_id': Decimal(str(scan_id)),
            'tenant_id': Decimal(str(tenant_id)),
            'case_id': Decimal(str(case_id)),
            'account_id': account_id,
            'started_at': started_at,
            'finished_at': None,
            'status': status,
            # GSI2: tenant#case#account별 최신 스캔 조회용
            'GSI2PK': f"TENANT#{tenant_id}#CASE#{case_id}#ACCOUNT#{account_id}",
            'GSI2SK': f"START#{started_at}#SCAN#{scan_id}"
        }

        self.table.put_item(Item=scan_metadata)
        return scan_metadata

    def get_scan_metadata(self, scan_id: int) -> Optional[Dict[str, Any]]:
        response = self.table.get_item(
            Key={
                'PK': f"SCAN#{scan_id}",
                'SK': 'METADATA'
            }
        )

        return response.get('Item')

    def update_scan_status(
        self,
        scan_id: int,
        status: str,
        finished_at: str = None
    ) -> None:
        update_expression = "SET #status = :status"
        expression_attribute_names = {"#status": "status"}
        expression_attribute_values = {":status": status}

        if finished_at:
            update_expression += ", finished_at = :finished_at"
            expression_attribute_values[":finished_at"] = finished_at

        self.table.update_item(
            Key={
                'PK': f"SCAN#{scan_id}",
                'SK': 'METADATA'
            },
            UpdateExpression=update_expression,
            ExpressionAttributeNames=expression_attribute_names,
            ExpressionAttributeValues=expression_attribute_values
        )

    def get_latest_scan_by_account(
        self,
        tenant_id: str,
        case_id: str,
        account_id: str
    ) -> Optional[Dict[str, Any]]:
        response = self.table.query(
            IndexName='GSI2',
            KeyConditionExpression='GSI2PK = :pk',
            ExpressionAttributeValues={
                ':pk': f"TENANT#{tenant_id}#CASE#{case_id}#ACCOUNT#{account_id}"
            },
            ScanIndexForward=False,  # 최신순 정렬
            Limit=1
        )

        items = response.get('Items', [])
        return items[0] if items else None

    def create_scan_log(
        self,
        scan_id: int,
        log_id: int,
        log_type: str,
        log_arn: str,
        log_region: str,
        account_id: str,
        created_at: str = None
    ) -> Dict[str, Any]:
        if not created_at:
            created_at = datetime.now().isoformat()

        scan_log = {
            'PK': f"SCAN#{scan_id}",
            'SK': f"LOG#{log_id}",
            'log_id': Decimal(str(log_id)),
            'log_type': log_type,
            'log_arn': log_arn,
            'log_region': log_region,
            'created_at': created_at,
            'GSI1PK': f"ACCOUNT#{account_id}#LOGTYPE#{log_type}#REG#{log_region}",
            'GSI1SK': f"SCAN#{scan_id}"
        }

        self.table.put_item(Item=scan_log)
        return scan_log

    def create_scan_log_destination(
        self,
        scan_id: int,
        log_id: int,
        dest_id: int,
        dest_type: str,
        dest_arn: str,
        dest_region: str,
        created_at: str = None
    ) -> Dict[str, Any]:
        if not created_at:
            created_at = datetime.now().isoformat()

        scan_log_dest = {
            'PK': f"SCAN#{scan_id}",
            'SK': f"LOG#{log_id}#DEST#{dest_id}",
            'dest_id': Decimal(str(dest_id)),
            'dest_type': dest_type,
            'dest_arn': dest_arn,
            'dest_region': dest_region,
            'created_at': created_at
        }

        self.table.put_item(Item=scan_log_dest)
        return scan_log_dest

    def get_scan_logs(self, scan_id: int) -> list:
        response = self.table.query(
            KeyConditionExpression='PK = :pk AND begins_with(SK, :sk_prefix)',
            ExpressionAttributeValues={
                ':pk': f"SCAN#{scan_id}",
                ':sk_prefix': 'LOG#'
            }
        )

        return response.get('Items', [])

    def create_collect_metadata(
        self,
        collect_id: int,
        scan_id: int,
        tenant_id: str,
        case_id: str,
        account_id: str,
        request_logs: list,
        created_at: str = None,
        status: str = 'RUNNING'
    ) -> Dict[str, Any]:
        if not created_at:
            created_at = datetime.now().isoformat()

        collect_metadata = {
            'PK': f"COLLECT#{collect_id}",
            'SK': 'METADATA',
            'collect_id': Decimal(str(collect_id)),
            'scan_id': Decimal(str(scan_id)),
            'tenant_id': Decimal(str(tenant_id)),
            'case_id': Decimal(str(case_id)),
            'account_id': account_id,
            'request_logs': request_logs,
            'created_at': created_at,
            'finished_at': None,
            'status': status
        }

        self.table.put_item(Item=collect_metadata)
        return collect_metadata

    def create_collect_task(
        self,
        collect_id: int,
        scan_id: int,
        log_id: int,
        log_type: str,
        dest_id: int,
        created_at: str = None,
        status: str = 'PENDING'
    ) -> Dict[str, Any]:
        if not created_at:
            created_at = datetime.now().isoformat()

        collect_task = {
            'PK': f"COLLECT#{collect_id}",
            'SK': f"SCAN#{scan_id}#LOG#{log_id}#DEST#{dest_id}",
            'scan_id': Decimal(str(scan_id)),
            'collect_id': Decimal(str(collect_id)),
            'log_id': Decimal(str(log_id)),
            'log_type': log_type,
            'dest_id': Decimal(str(dest_id)),
            'created_at': created_at,
            'finished_at': None,
            'status': status
        }

        self.table.put_item(Item=collect_task)
        return collect_task
