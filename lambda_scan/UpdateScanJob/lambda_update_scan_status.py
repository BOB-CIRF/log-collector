import json
import os
from datetime import datetime
from dynamodb_repository import DynamoDBRepository


def handler(event, context=None):
    try:
        scan_id = event.get("scan_id")
        status = event.get("status", "SUCCEEDED")

        if not scan_id:
            raise ValueError("scan_id is required")

        # DynamoDB repository 초기화
        repo = DynamoDBRepository()

        # 현재 시간
        finished_at = datetime.now().isoformat()

        # scan 상태 업데이트
        repo.update_scan_status(
            scan_id=scan_id,
            status=status,
            finished_at=finished_at
        )

        return {
            "scan_id": scan_id,
            "status": status,
            "finished_at": finished_at,
            "message": f"Scan {scan_id} updated to {status}"
        }

    except Exception as e:
        print(f"Error updating scan status: {str(e)}")
        raise