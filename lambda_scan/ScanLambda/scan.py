import json
import boto3
from botocore.config import Config
import logging
from utils import _safe, _get_s3_bucket_region, _resolve_log_destination_with_arn, _resolve_log_destination_of_vpc, _resolve_log_destination_of_waf, _get_firehose_destination, _get_subscription_filter_destination
from enums import DestLogsType, ResourceType
# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

RETRIES = Config(retries={'max_attempts': 10, 'mode': 'standard'})

# ============================================================
# 1. CloudTrail (S3 / CloudTrail Lake)
# ============================================================
def scan_cloudtrail(sess, region, account_id):
    ct = sess.client("cloudtrail", region_name=region, config=RETRIES)
    results = []

    trails = _safe(ct.list_trails)
    if "_error" in trails:
        return results

    trails_list = trails.get("Trails", [])

    for t in trails_list:
        trail_arn = t.get("TrailARN", "")
        name = t.get("Name") or trail_arn.split("/")[-1]

        # Get trail config to find home region
        trail_config = _safe(ct.get_trail, Name=name)
        if "_error" in trail_config:
            continue

        trail = trail_config.get("Trail", {})
        home_region = trail.get("HomeRegion", region)
        print(home_region)
        # Only process in home region to avoid duplicates
        if home_region != region:
            continue

        # Get status
        st = _safe(ct.get_trail_status, Name=name)
        is_logging = bool(st.get("IsLogging", False)) if "_error" not in st else False

        # enabled가 아니면 skip
        if not is_logging:
            continue

        # S3 bucket destination with prefix
        s3_bucket = trail.get("S3BucketName")
        s3_prefix = trail.get("S3KeyPrefix", "")
        if s3_bucket:
            dest_arn = f"arn:aws:s3:::{s3_bucket}/{s3_prefix}" if s3_prefix else f"arn:aws:s3:::{s3_bucket}"
        else:
            dest_arn = None

        results.append({
            "log_type": ResourceType.CLOUDTRAIL.value,
            "log_detail": name,
            "log_arn": trail_arn,
            "log_region": home_region,
            "destination": _resolve_log_destination_with_arn(sess, dest_arn, home_region, account_id)
        })

    # CloudTrail Lake
    event_data_stores = _safe(ct.list_event_data_stores)
    print(event_data_stores)
    """
    {'EventDataStores': [], 'ResponseMetadata': {'RequestId': '5548b279-9e04-4915-8790-88f8a3cb03a5', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': '5548b279-9e04-4915-8790-88f8a3cb03a5', 'content-type': 'application/x-amz-json-1.1', 'content-length': '22', 'date': 'Mon, 06 Oct 2025 16:40:48 GMT'}, 'RetryAttempts': 0}}
    """
    if len(event_data_stores) != 0:
        for eds in event_data_stores.get("EventDataStores", []):
            if eds.get("Status") == "ENABLED":
                eds_arn = eds.get("EventDataStoreArn")
                results.append({
                    "log_type": ResourceType.CLOUDTRAIL.value,
                    "log_detail": eds.get("Name"),
                    "log_arn": eds_arn,
                    "log_region": region,
                    "destination": [
                        {
                            "destination_arn": eds_arn,
                            "destination_type": DestLogsType.CT_LAKE.value,
                            "destination_region": region
                        }
                    ]
                })

    return results


# ============================================================
# 2. S3 Server Access Logging (S3)
# ============================================================
def scan_s3_logging(sess, account_id):
    """S3 is a global service - only call this from one region (us-east-1)"""
    s3 = sess.client("s3", config=RETRIES)
    results = []

    buckets = _safe(s3.list_buckets)

    if "_error" in buckets:
        return results

    for bucket in buckets.get("Buckets", []):
        bucket_name = bucket.get("Name")
        print(bucket_name)
        # Get bucket region for destination resolution
        location = _safe(s3.get_bucket_location, Bucket=bucket_name)
        bucket_region = location.get("LocationConstraint") or "us-east-1" if "_error" not in location else "unknown"

        # Get logging config
        logging = _safe(s3.get_bucket_logging, Bucket=bucket_name)

        if "LoggingEnabled" not in logging:
            continue

        # Destination S3 bucket with prefix
        logging_enabled = logging.get("LoggingEnabled", {})
        target_bucket = logging_enabled.get("TargetBucket")
        target_prefix = logging_enabled.get("TargetPrefix", "")
        if target_bucket:
            dest_arn = f"arn:aws:s3:::{target_bucket}/{target_prefix}" if target_prefix else f"arn:aws:s3:::{target_bucket}"
        else:
            dest_arn = None

        results.append({
            "log_type": ResourceType.S3_ACCESS.value,
            "log_detail": bucket_name,
            "log_arn": f"arn:aws:s3:::{bucket_name}",
            "log_region": bucket_region,  # Use actual bucket region
            "destination": _resolve_log_destination_with_arn(sess, dest_arn, bucket_region, account_id)
        })

    return results


# ============================================================
# 3. VPC Flow Logs (S3 / CWL / KINESIS)
# ============================================================
def check_vpc_flow_logs_resource(region, account_id, resource_id):
    if resource_id.startswith("vpc-"):
        resource_arn = f"arn:aws:ec2:{region}:{account_id}:vpc/{resource_id}"
    elif resource_id.startswith("subnet-"):
        resource_arn = f"arn:aws:ec2:{region}:{account_id}:subnet/{resource_id}"
    elif resource_id.startswith("eni-"):
        resource_arn = f"arn:aws:ec2:{region}:{account_id}:network-interface/{resource_id}"
    else:
        resource_arn = resource_id

    return resource_arn

def scan_vpc_flow_logs(sess, region, account_id):
    ec2 = sess.client("ec2", region_name=region, config=RETRIES)
    results = []

    # VPC 목록 조회
    vpcs_result = _safe(ec2.describe_vpcs)
    print(vpcs_result)
    if "_error" in vpcs_result:
        return results

    for vpc in vpcs_result.get("Vpcs", []):
        vpc_id = vpc.get("VpcId")
        vpc_arn = f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}"

        # 해당 VPC의 flow log 조회
        flow_logs_result = _safe(ec2.describe_flow_logs, Filters=[
            {"Name": "resource-id", "Values": [vpc_id]}
        ])

        if "_error" in flow_logs_result:
            continue

        # ACTIVE 상태인 flow log만 필터링하고 목적지 수집
        destinations = []
        for fl in flow_logs_result.get("FlowLogs", []):
            if fl.get("FlowLogStatus") == "ACTIVE":
                dests = _resolve_log_destination_of_vpc(sess, fl, region, account_id)
                destinations.extend(dests)

        if not destinations:
            continue

        results.append({
            "log_type": ResourceType.VPC.value,
            "log_detail": vpc_id,
            "log_arn": vpc_arn,
            "log_region": region,
            "destination": destinations
        })

    return results


# ============================================================
# 4. API Gateway
# ============================================================
def scan_api_gateway(sess, region, account_id):
    results = []

    # API Gateway v1 (REST API)
    apigw = sess.client("apigateway", region_name=region, config=RETRIES)
    apis_v1 = _safe(apigw.get_rest_apis, limit=500)

    if "_error" not in apis_v1:
        for api in apis_v1.get("items", []):
            api_id = api.get("id")
            api_name = api.get("name")
            stages = _safe(apigw.get_stages, restApiId=api_id)

            if "_error" not in stages:
                for stage in stages.get("item", []):
                    stage_name = stage.get("stageName")

                    # Access Log
                    if "accessLogSettings" in stage:
                        dest_arn = stage.get("accessLogSettings", {}).get("destinationArn")

                        results.append({
                            "log_type": ResourceType.API_GW.value,
                            "log_detail": f"{api_name}/{stage_name}",
                            "log_arn": f"arn:aws:apigateway:{region}::/restapis/{api_id}/stages/{stage_name}",
                            "log_region": region,
                            "destination": _resolve_log_destination_with_arn(sess, dest_arn, region, account_id)
                        })

    # API Gateway v2 (HTTP/WebSocket API)
    apigw2 = sess.client("apigatewayv2", region_name=region, config=RETRIES)
    apis_v2 = _safe(apigw2.get_apis)

    if "_error" not in apis_v2:
        for api in apis_v2.get("Items", []):
            api_id = api.get("ApiId")
            api_name = api.get("Name")
            stages = _safe(apigw2.get_stages, ApiId=api_id)

            if "_error" not in stages:
                for stage in stages.get("Items", []):
                    stage_name = stage.get("StageName")

                    # Access Log
                    if "AccessLogSettings" in stage:
                        dest_arn = stage.get("AccessLogSettings", {}).get("DestinationArn")

                        results.append({
                            "log_type": ResourceType.API_GW.value,
                            "log_detail": f"{api_name}/{stage_name}",
                            "log_arn": f"arn:aws:apigateway:{region}::/apis/{api_id}/stages/{stage_name}",
                            "log_region": region,
                            "destination": _resolve_log_destination_with_arn(sess, dest_arn, region, account_id)
                        })

    return results


# ============================================================
# 5. ELB/ALB/NLB Access Logs
# ============================================================
def scan_elb_logs(sess, region, account_id):
    results = []

    # ALB/NLB (ELBv2)
    elbv2 = sess.client("elbv2", region_name=region, config=RETRIES)
    lbs = _safe(elbv2.describe_load_balancers)

    if "_error" not in lbs:
        for lb in lbs.get("LoadBalancers", []):
            lb_arn = lb.get("LoadBalancerArn")
            attrs = _safe(elbv2.describe_load_balancer_attributes, LoadBalancerArn=lb_arn)

            if "_error" not in attrs:
                attr_dict = {a["Key"]: a["Value"] for a in attrs.get("Attributes", [])}

                # enabled가 아니면 skip
                if attr_dict.get("access_logs.s3.enabled") != "true":
                    continue

                # S3 bucket destination with prefix
                s3_bucket = attr_dict.get("access_logs.s3.bucket")
                s3_prefix = attr_dict.get("access_logs.s3.prefix", "")
                if s3_bucket:
                    dest_arn = f"arn:aws:s3:::{s3_bucket}/{s3_prefix}" if s3_prefix else f"arn:aws:s3:::{s3_bucket}"
                else:
                    dest_arn = None

                results.append({
                    "log_type": ResourceType.ELB.value,
                    "log_detail": lb.get("LoadBalancerName"),
                    "log_arn": lb_arn,
                    "log_region": region,
                    "destination": _resolve_log_destination_with_arn(sess, dest_arn, region, account_id)
                })

    return results


# ============================================================
# 6. CloudFront
# ============================================================
def scan_cloudfront(sess, account_id):
    cf = sess.client("cloudfront", config=RETRIES)
    results = []

    distributions = _safe(cf.list_distributions)
    if "_error" in distributions:
        return results

    for dist in distributions.get("DistributionList", {}).get("Items", []):
        dist_id = dist.get("Id")
        config = _safe(cf.get_distribution_config, Id=dist_id)

        if "_error" not in config:
            logging = config.get("DistributionConfig", {}).get("Logging", {})

            # enabled가 아니면 skip
            if not logging.get("Enabled"):
                continue

            # S3 bucket destination with prefix
            s3_bucket = logging.get("Bucket")
            s3_prefix = logging.get("Prefix", "")
            # CloudFront의 Bucket 필드는 도메인 형식(xxx.s3.amazonaws.com)일 수 있음
            if s3_bucket and ".s3." in s3_bucket:
                bucket_name = s3_bucket.split(".s3.")[0]
            else:
                bucket_name = s3_bucket

            if bucket_name:
                dest_arn = f"arn:aws:s3:::{bucket_name}/{s3_prefix}" if s3_prefix else f"arn:aws:s3:::{bucket_name}"
            else:
                dest_arn = None

            results.append({
                "log_type": ResourceType.CLOUDFRONT.value,
                "log_detail": dist.get("DomainName"),
                "log_arn": dist.get("ARN"),
                "log_region": "global",
                "destination": _resolve_log_destination_with_arn(sess, dest_arn, "global", account_id)
            })

    return results


# ============================================================
# 7. AWS Config
# ============================================================
def scan_config(sess, region, account_id):
    cfg = sess.client("config", region_name=region, config=RETRIES)
    results = []

    recorders = _safe(cfg.describe_configuration_recorders)
    status = _safe(cfg.describe_configuration_recorder_status)

    if "_error" not in recorders and "_error" not in status:
        recorders_list = recorders.get("ConfigurationRecorders", [])
        status_dict = {s["name"]: s for s in status.get("ConfigurationRecordersStatus", [])}

        for recorder in recorders_list:
            recorder_name = recorder.get("name")
            is_recording = status_dict.get(recorder_name, {}).get("recording", False)

            # enabled가 아니면 skip
            if not is_recording:
                continue

            # Config는 S3 bucket으로 전송
            role_arn = recorder.get("roleARN")
            # delivery channel에서 S3 bucket 확인
            delivery_channels = _safe(cfg.describe_delivery_channels)
            dest_arn = None
            if "_error" not in delivery_channels:
                channels = delivery_channels.get("DeliveryChannels", [])
                if channels:
                    s3_bucket = channels[0].get("s3BucketName")
                    s3_prefix = channels[0].get("s3KeyPrefix", "")
                    if s3_bucket:
                        dest_arn = f"arn:aws:s3:::{s3_bucket}/{s3_prefix}" if s3_prefix else f"arn:aws:s3:::{s3_bucket}"

            results.append({
                "log_type": ResourceType.CONFIG.value,
                "log_detail": recorder_name,
                "log_arn": f"arn:aws:config:{region}:{account_id}:config-recorder/{recorder_name}",
                "log_region": region,
                "destination": _resolve_log_destination_with_arn(sess, dest_arn, region, account_id)
            })

    return results


# ============================================================
# 11. RDS/Aurora Audit Logs
# ============================================================
def scan_rds_audit_logs(sess, region, account_id):
    rds = sess.client("rds", region_name=region, config=RETRIES)
    results = []

    # RDS Instances
    instances = _safe(rds.describe_db_instances)
    if "_error" not in instances:
        for db in instances.get("DBInstances", []):
            enabled_logs = db.get("EnabledCloudwatchLogsExports", [])

            # Audit 로그가 활성화되어 있는지 확인
            # MySQL/MariaDB: "audit", PostgreSQL: "postgresql" (audit 포함)
            has_audit = any(log_type in ["audit"] for log_type in enabled_logs)

            if not has_audit:
                continue

            log_group_name = f"/aws/rds/instance/{db.get('DBInstanceIdentifier')}/audit"

            # CloudWatch Logs 구독 필터 확인 (최종 목적지 찾기)
            destination = _get_subscription_filter_destination(sess, log_group_name, region, account_id)

            results.append({
                "log_type": ResourceType.RDS_AUDIT.value,
                "log_detail": db.get("DBInstanceIdentifier"),
                "log_arn": db.get("DBInstanceArn"),
                "log_region": region,
                "destination": destination
            })

    # Aurora Clusters
    clusters = _safe(rds.describe_db_clusters)
    if "_error" not in clusters:
        for cluster in clusters.get("DBClusters", []):
            enabled_logs = cluster.get("EnabledCloudwatchLogsExports", [])

            # Audit 로그가 활성화되어 있는지 확인
            has_audit = any(log_type in ["audit"] for log_type in enabled_logs)

            if not has_audit:
                continue

            log_group_name = f"/aws/rds/cluster/{cluster.get('DBClusterIdentifier')}/audit"

            # CloudWatch Logs 구독 필터 확인 (최종 목적지 찾기)
            destination = _get_subscription_filter_destination(sess, log_group_name, region, account_id)

            results.append({
                "log_type": ResourceType.RDS_AUDIT.value,
                "log_detail": cluster.get("DBClusterIdentifier"),
                "log_arn": cluster.get("DBClusterArn"),
                "log_region": region,
                "destination": destination
            })

    return results


# ============================================================
# 12. Redshift Audit Logs
# ============================================================
def scan_redshift_audit_logs(sess, region, account_id):
    redshift = sess.client("redshift", region_name=region, config=RETRIES)
    results = []

    # List all Redshift clusters
    clusters = _safe(redshift.describe_clusters)
    if "_error" in clusters:
        return results

    for cluster in clusters.get("Clusters", []):
        cluster_id = cluster.get("ClusterIdentifier")
        cluster_arn = f"arn:aws:redshift:{region}:{account_id}:cluster:{cluster_id}"

        # Get logging status
        logging_status = _safe(redshift.describe_logging_status, ClusterIdentifier=cluster_id)

        if "_error" not in logging_status:
            logging_enabled = logging_status.get("LoggingEnabled", False)

            # Logging이 비활성화되어 있으면 skip
            if not logging_enabled:
                continue

            # S3 bucket and prefix
            s3_bucket = logging_status.get("BucketName")
            s3_prefix = logging_status.get("S3KeyPrefix", "")

            if s3_bucket:
                dest_arn = f"arn:aws:s3:::{s3_bucket}/{s3_prefix}" if s3_prefix else f"arn:aws:s3:::{s3_bucket}"
            else:
                dest_arn = None

            dest_region = _get_s3_bucket_region(sess, s3_bucket) if s3_bucket else None

            results.append({
                "log_type": ResourceType.REDSHIFT_AUDIT.value,
                "log_detail": cluster_id,
                "log_arn": cluster_arn,
                "log_region": region,
                "destination": [
                    {
                        "destination_arn": dest_arn,
                        "destination_type": DestLogsType.S3.value,
                        "destination_region": dest_region
                    }
                ]
            })

    return results


# ============================================================
# 13. FSx Audit Logs (Windows File Server)
# ============================================================
def scan_fsx_audit_logs(sess, region, account_id):
    fsx = sess.client("fsx", region_name=region, config=RETRIES)
    results = []

    # List all FSx file systems
    file_systems = _safe(fsx.describe_file_systems)
    if "_error" in file_systems:
        return results

    for fs in file_systems.get("FileSystems", []):
        fs_id = fs.get("FileSystemId")
        fs_type = fs.get("FileSystemType")
        fs_arn = fs.get("ResourceARN")

        # Only Windows file systems have audit logs
        if fs_type != "WINDOWS":
            continue

        windows_config = fs.get("WindowsConfiguration", {})
        audit_config = windows_config.get("AuditLogConfiguration", {})

        # Check if audit logging is enabled
        audit_log_dest = audit_config.get("FileAccessAuditLogLevel", "DISABLED")

        # Skip if audit logging is disabled
        if audit_log_dest == "DISABLED":
            continue

        # FSx audit logs go to CloudWatch Logs: /aws/fsx/windows/{filesystem-id}
        log_group_name = f"/aws/fsx/windows/{fs_id}"

        # Check for subscription filters to find final destination
        destination = _get_subscription_filter_destination(sess, log_group_name, region, account_id)

        results.append({
            "log_type": ResourceType.FSX.value,
            "log_detail": fs_id,
            "log_arn": fs_arn,
            "log_region": region,
            "destination": destination
        })

    return results


# ============================================================
# 14. Client VPN Logs
# ============================================================
def scan_client_vpn_logs(sess, region, account_id):
    ec2 = sess.client("ec2", region_name=region, config=RETRIES)
    results = []

    # Describe all Client VPN endpoints
    vpn_endpoints = _safe(ec2.describe_client_vpn_endpoints)
    if "_error" in vpn_endpoints:
        return results

    for endpoint in vpn_endpoints.get("ClientVpnEndpoints", []):
        endpoint_id = endpoint.get("ClientVpnEndpointId")
        endpoint_arn = f"arn:aws:ec2:{region}:{account_id}:client-vpn-endpoint/{endpoint_id}"

        # Check connection logging configuration
        conn_log_options = endpoint.get("ConnectionLogOptions", {})
        conn_log_enabled = conn_log_options.get("Enabled", False)

        if not conn_log_enabled:
            continue

        # CloudWatch Logs log group
        log_group_name = conn_log_options.get("CloudwatchLogGroup")
        if not log_group_name:
            continue

        # Check for subscription filters to find final destination
        destination = _get_subscription_filter_destination(sess, log_group_name, region, account_id)

        results.append({
            "log_type": ResourceType.CLIENT_VPN.value,
            "log_detail": endpoint_id,
            "log_arn": endpoint_arn,
            "log_region": region,
            "destination": destination
        })

    return results


# ============================================================
# 15. WorkSpaces Logs
# ============================================================
def scan_workspaces_logs(sess, region, account_id):
    workspaces = sess.client("workspaces", region_name=region, config=RETRIES)
    results = []

    # Describe all WorkSpaces directories
    directories = _safe(workspaces.describe_workspace_directories)
    if "_error" in directories:
        return results

    for directory in directories.get("Directories", []):
        directory_id = directory.get("DirectoryId")
        directory_arn = f"arn:aws:workspaces:{region}:{account_id}:directory/{directory_id}"

        # Check WorkSpace creation properties for logging
        workspace_creation_props = directory.get("WorkspaceCreationProperties", {})
        user_enabled_as_local_admin = workspace_creation_props.get("UserEnabledAsLocalAdministrator", False)

        # Describe workspace bundles to check for logging configuration
        # Note: WorkSpaces doesn't have a direct API for logging status
        # Logging is configured at the directory level via CloudWatch Logs

        # WorkSpaces logs go to CloudWatch Logs
        # Log groups: /aws/workspaces/{WorkspaceId}
        # We need to list workspaces for this directory
        ws_list = _safe(workspaces.describe_workspaces, DirectoryId=directory_id)
        if "_error" in ws_list:
            continue

        for ws in ws_list.get("Workspaces", []):
            ws_id = ws.get("WorkspaceId")
            ws_arn = f"arn:aws:workspaces:{region}:{account_id}:workspace/{ws_id}"

            # WorkSpaces automatically logs to CloudWatch Logs when enabled
            # Log group name pattern: /aws/workspaces/{workspace-id}
            log_group_name = f"/aws/workspaces/{ws_id}"

            # Default destination: CloudWatch Logs
            dest_arn = f"arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}"
            dest_type = "CWL"
            dest_region = region

            results.append({
                "log_type": "workspaces",
                "log_detail": ws_id,
                "log_arn": ws_arn,
                "log_region": region,
                "destination": [
                    {
                        "destination_arn": dest_arn,
                        "destination_type": dest_type,
                        "destination_region": dest_region
                    }
                ]
            })

    return results


# ============================================================
# 16. Route 53 Resolver Query Logs (VPC)
# ============================================================
def scan_route53_resolver_logs(sess, region, account_id):
    r53r = sess.client("route53resolver", region_name=region, config=RETRIES)
    results = []

    configs = _safe(r53r.list_resolver_query_log_configs)
    if "_error" in configs:
        return results

    for config in configs.get("ResolverQueryLogConfigs", []):
        config_id = config.get("Id")

        # Check associations
        assocs = _safe(r53r.list_resolver_query_log_config_associations,
                      ResolverQueryLogConfigId=config_id)

        # ACTIVE 상태가 아니면 skip
        enabled = False
        if "_error" not in assocs:
            enabled = any(a.get("Status") == "ACTIVE"
                         for a in assocs.get("ResolverQueryLogConfigAssociations", []))

        if not enabled:
            continue

        # Destination ARN 확인
        dest_arn = config.get("DestinationArn")

        results.append({
            "log_type": ResourceType.ROUTE53_RESOLVER.value,
            "log_detail": config.get("Name"),
            "log_arn": config.get("Arn"),
            "log_region": region,
            "destination": _resolve_log_destination_with_arn(sess, dest_arn, region, account_id)
        })

    return results


# ============================================================
# 13. WAFv2
# ============================================================
def scan_wafv2(sess, region, account_id):
    results = []

    # Regional WAF
    waf = sess.client("wafv2", region_name=region, config=RETRIES)
    regional_configs = _safe(waf.list_logging_configurations, Scope="REGIONAL")

    if "_error" not in regional_configs:
        for config in regional_configs.get("LoggingConfigurations", []):
            results.append({
                "log_type": ResourceType.WAF.value,
                "log_detail": config.get("ResourceArn").split("/")[-1],
                "log_arn": config.get("ResourceArn"),
                "log_region": region,
                "destination": _resolve_log_destination_of_waf(sess, config, region, account_id)
            })

    return results


def scan_wafv2_global(sess, account_id):
    """WAF for CloudFront (us-east-1 only)"""
    results = []

    waf = sess.client("wafv2", region_name="us-east-1", config=RETRIES)
    cloudfront_configs = _safe(waf.list_logging_configurations, Scope="CLOUDFRONT")

    if "_error" not in cloudfront_configs:
        for config in cloudfront_configs.get("LoggingConfigurations", []):
            results.append({
                "log_type": ResourceType.WAF.value,
                "log_detail": config.get("ResourceArn").split("/")[-1],
                "log_arn": config.get("ResourceArn"),
                "log_region": "global",
                "destination": _resolve_log_destination_of_waf(sess, config, "us-east-1", account_id)
            })

    return results


# ============================================================
# 14. EKS Control Plane Logs
# ============================================================
def scan_eks_logs(sess, region, account_id):
    eks = sess.client("eks", region_name=region, config=RETRIES)
    results = []

    clusters = _safe(eks.list_clusters)
    if "_error" in clusters:
        return results

    for cluster_name in clusters.get("clusters", []):
        cluster = _safe(eks.describe_cluster, name=cluster_name)

        if "_error" not in cluster:
            logging_config = cluster.get("cluster", {}).get("logging", {}).get("clusterLogging", [])

            enabled_types = []
            for log_config in logging_config:
                if log_config.get("enabled"):
                    enabled_types.extend(log_config.get("types", []))

            # enabled가 아니면 skip
            if not enabled_types:
                continue

            log_group_name = f"/aws/eks/{cluster_name}/cluster"

            # CloudWatch Logs 구독 필터 확인 (최종 목적지 찾기)
            destination = _get_subscription_filter_destination(sess, log_group_name, region, account_id)

            results.append({
                "log_type": ResourceType.EKS.value,
                "log_detail": cluster_name,
                "log_arn": cluster.get("cluster", {}).get("arn"),
                "log_region": region,
                "destination": destination
            })

    return results


# ============================================================
# 14. Network Firewall Logs
# ============================================================
def scan_network_firewall_logs(sess, region, account_id):
    """Network Firewall Logs 스캔"""
    nfw = sess.client("network-firewall", region_name=region, config=RETRIES)
    results = []

    # List all firewalls
    firewalls = _safe(nfw.list_firewalls)
    if "_error" in firewalls:
        return results

    for firewall in firewalls.get("Firewalls", []):
        firewall_name = firewall.get("FirewallName")
        firewall_arn = firewall.get("FirewallArn")

        # Get logging configuration
        logging_config = _safe(nfw.describe_logging_configuration, FirewallArn=firewall_arn)

        if "_error" not in logging_config:
            log_configs = logging_config.get("LoggingConfiguration", {}).get("LogDestinationConfigs", [])

            # Network Firewall은 Alert Logs와 Flow Logs 두 가지 타입이 있음
            for log_config in log_configs:
                log_type_detail = log_config.get("LogType")  # "ALERT" or "FLOW"
                log_destination_type = log_config.get("LogDestinationType")  # "S3", "CloudWatchLogs", "KinesisDataFirehose"
                log_destination = log_config.get("LogDestination", {})

                # Destination ARN 생성
                if log_destination_type == "S3":
                    bucket_name = log_destination.get("bucketName")
                    prefix = log_destination.get("prefix", "")
                    if bucket_name:
                        dest_arn = f"arn:aws:s3:::{bucket_name}/{prefix}" if prefix else f"arn:aws:s3:::{bucket_name}"
                        dest_region = _get_s3_bucket_region(sess, bucket_name)
                    else:
                        dest_arn = None
                        dest_region = None
                    destinations = [{
                        "destination_arn": dest_arn,
                        "destination_type": "S3",
                        "destination_region": dest_region
                    }]

                elif log_destination_type == "CloudWatchLogs":
                    log_group = log_destination.get("logGroup")
                    if log_group:
                        dest_arn = f"arn:aws:logs:{region}:{account_id}:log-group:{log_group}"
                    else:
                        dest_arn = None
                    destinations = [{
                        "destination_arn": dest_arn,
                        "destination_type": "CWL",
                        "destination_region": region
                    }]

                elif log_destination_type == "KinesisDataFirehose":
                    delivery_stream = log_destination.get("deliveryStream")
                    if delivery_stream:
                        firehose_arn = f"arn:aws:firehose:{region}:{account_id}:deliverystream/{delivery_stream}"
                        destinations = _get_firehose_destination(sess, firehose_arn, region)
                    else:
                        destinations = [{
                            "destination_arn": None,
                            "destination_type": "FIREHOSE",
                            "destination_region": region
                        }]
                else:
                    destinations = [{
                        "destination_arn": None,
                        "destination_type": "UNKNOWN",
                        "destination_region": None
                    }]

                results.append({
                    "log_type": ResourceType.FW_ALERT.value if log_type_detail.lower() == "ALERT" else ResourceType.FW_FLOW.value,
                    "log_detail": firewall_name,
                    "log_arn": firewall_arn,
                    "log_region": region,
                    "destination": destinations
                })

    return results


def scan_transit_gateway_flow_logs(sess, region, account_id):
    ec2 = sess.client("ec2", region_name=region, config=RETRIES)
    results = []

    # List all Transit Gateways
    tgws = _safe(ec2.describe_transit_gateways)
    if "_error" in tgws:
        return results

    for tgw in tgws.get("TransitGateways", []):
        tgw_id = tgw.get("TransitGatewayId")
        tgw_arn = tgw.get("TransitGatewayArn")

        # Transit Gateway Flow Logs는 VPC Flow Logs API 사용
        # ResourceId가 tgw-xxxxx인 Flow Logs 찾기
        flow_logs = _safe(ec2.describe_flow_logs, Filters=[
            {"Name": "resource-id", "Values": [tgw_id]}
        ])

        if "_error" not in flow_logs:
            for fl in flow_logs.get("FlowLogs", []):
                # ACTIVE 상태가 아니면 skip
                if fl.get("FlowLogStatus") != "ACTIVE":
                    continue

                flow_log_id = fl.get("FlowLogId")

                results.append({
                    "log_type": ResourceType.TRANSIT_GW.value,
                    "log_detail": f"{tgw_id}/{flow_log_id}",
                    "log_arn": tgw_arn,
                    "log_region": region,
                    "destination": _resolve_log_destination_of_vpc(sess, fl, region, account_id)
                })

    return results


def scan_session_manager_logs(sess, region, account_id):
    ssm = sess.client("ssm", region_name=region, config=RETRIES)
    results = []

    doc_name = "SSM-SessionManagerRunShell"
    doc = _safe(ssm.get_document, Name=doc_name)

    if "_error" not in doc:
        try:
            import json
            doc_content = json.loads(doc.get("Content", "{}"))
            inputs = doc_content.get("inputs", {})

            s3_bucket_name = inputs.get("s3BucketName")
            s3_key_prefix = inputs.get("s3KeyPrefix", "")
            cloudwatch_log_group_name = inputs.get("cloudWatchLogGroupName")

            # S3 destination
            if s3_bucket_name:
                if s3_key_prefix:
                    dest_arn = f"arn:aws:s3:::{s3_bucket_name}/{s3_key_prefix}"
                else:
                    dest_arn = f"arn:aws:s3:::{s3_bucket_name}"
                dest_region = _get_s3_bucket_region(sess, s3_bucket_name)
                dest_type = "S3"

                results.append({
                    "log_type": ResourceType.SSM.value,
                    "log_detail": "S3",
                    "log_arn": f"arn:aws:ssm:{region}:{account_id}:document/{doc_name}",
                    "log_region": region,
                    "destination": [
                        {
                            "destination_arn": dest_arn,
                            "destination_type": dest_type,
                            "destination_region": dest_region
                        }
                    ]
                })

            # CloudWatch Logs destination
            if cloudwatch_log_group_name:
                dest_arn = f"arn:aws:logs:{region}:{account_id}:log-group:{cloudwatch_log_group_name}"

                results.append({
                    "log_type": ResourceType.SSM.value,
                    "log_detail": "CloudWatch Logs",
                    "log_arn": f"arn:aws:ssm:{region}:{account_id}:document/{doc_name}",
                    "log_region": region,
                    "destination": [
                        {
                            "destination_arn": dest_arn,
                            "destination_type": DestLogsType.CWL.value,
                            "destination_region": region
                        }
                    ]
                })

        except Exception as e:
            logger.warning(f"Failed to parse Session Manager document: {str(e)}")

    return results


def scan_global_accelerator(sess, account_id):
    """Global Accelerator Flow Logs 스캔 (us-west-2 리전에서만 실행)"""
    ga = sess.client("globalaccelerator", region_name="us-west-2", config=RETRIES)
    results = []

    accelerators = _safe(ga.list_accelerators)
    if "_error" in accelerators:
        return results

    for accelerator in accelerators.get("Accelerators", []):
        accelerator_arn = accelerator.get("AcceleratorArn")
        accelerator_name = accelerator.get("Name")

        # Get accelerator attributes (flow logs configuration)
        attrs = _safe(ga.describe_accelerator_attributes, AcceleratorArn=accelerator_arn)

        if "_error" not in attrs:
            attributes = attrs.get("AcceleratorAttributes", {})
            flow_logs_enabled = attributes.get("FlowLogsEnabled", False)

            # Flow logs가 활성화되지 않았으면 skip
            if not flow_logs_enabled:
                continue

            # S3 bucket and prefix
            s3_bucket = attributes.get("FlowLogsS3Bucket")
            s3_prefix = attributes.get("FlowLogsS3Prefix", "")

            if s3_bucket:
                dest_arn = f"arn:aws:s3:::{s3_bucket}/{s3_prefix}" if s3_prefix else f"arn:aws:s3:::{s3_bucket}"
            else:
                dest_arn = None
            dest_region = _get_s3_bucket_region(sess, s3_bucket) if s3_bucket else None

            results.append({
                "log_type": ResourceType.GLOBAL_ACCELERATOR.value,
                "log_detail": accelerator_name,
                "log_arn": accelerator_arn,
                "log_region": "global",
                "destination": [
                    {
                        "destination_arn": dest_arn,
                        "destination_type": DestLogsType.S3.value,
                        "destination_region": dest_region
                    }
                ]
            })

    return results
