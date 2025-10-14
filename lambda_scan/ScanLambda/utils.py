import boto3
from botocore.config import Config
import logging
from enums import DestLogsType, FirehoseDestType

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

RETRIES = Config(retries={'max_attempts': 10, 'mode': 'standard'})

def _assume(sess, role_arn=None, external_id=None):
    if not role_arn:
        return sess
    sts = sess.client("sts", config=RETRIES)
    kwargs = {"RoleArn": role_arn, "RoleSessionName": "aws-log-scan"}
    if external_id:
        kwargs["ExternalId"] = external_id
    creds = sts.assume_role(**kwargs)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    
def _safe(fn, **kw):
    try:
        return fn(**kw)
    except Exception as e:
        return {"_error": str(e)}

def _get_s3_bucket_region(sess, bucket_name):
    if not bucket_name:
        return None

    try:
        s3 = sess.client("s3", config=RETRIES)
        location = s3.get_bucket_location(Bucket=bucket_name)
        region = location.get("LocationConstraint") or "us-east-1"
        return region
    except Exception as e:
        logger.warning(f"Failed to get region for bucket {bucket_name}: {str(e)}")
        return None

def _parse_s3_bucket_info(sess, destination, param):
    s3_dest = destination[param]
    bucket_arn = s3_dest.get("BucketARN")
    s3_prefix = s3_dest.get("Prefix", "")
    bucket_name = bucket_arn.split(":::")[1] if bucket_arn else None
    dest_region = _get_s3_bucket_region(sess, bucket_name) if bucket_name else None

    if bucket_name:
        dest_arn = f"{bucket_arn}/{s3_prefix}" if s3_prefix else bucket_arn
    else:
        dest_arn = bucket_arn

    return {
                "destination_arn": dest_arn,
                "destination_type": DestLogsType.S3.value,
                "destination_region": dest_region
            }

# Firehose ARN에서 최종 목적지 정보를 추출하는 함수입니다.
def _get_firehose_destination(sess, firehose_arn, region) -> list:
    results = []

    if not firehose_arn:
        return None, None, None

    stream_name = firehose_arn.split("/")[-1] if "/" in firehose_arn else None

    if not stream_name:
        results.append({
                    "destination_arn": firehose_arn,
                    "destination_type": DestLogsType.FIREHOSE.value,
                    "destination_region": region
                })
        return results

    try:
        firehose = sess.client("firehose", region_name=region, config=RETRIES)
        stream_desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)

        destinations = stream_desc.get("DeliveryStreamDescription", {}).get("Destinations", [])
        print(destinations)
        if not destinations:
            results.append({
                    "destination_arn": firehose_arn,
                    "destination_type": DestLogsType.FIREHOSE.value,
                    "destination_region": region
                })
            return results

        for destination in destinations:
            if FirehoseDestType.EX_S3.value in destination:
                results.append(_parse_s3_bucket_info(sess, destination, FirehoseDestType.EX_S3.value))
            elif FirehoseDestType.S3.value in destination:
                results.append(_parse_s3_bucket_info(sess, destination, FirehoseDestType.S3.value))
            elif FirehoseDestType.REDSHIFT.value in destination:
                redshift_dest = destination[FirehoseDestType.REDSHIFT.value]
                dest_arn = redshift_dest.get("ClusterJDBCURL")
                results.append({
                    "destination_arn": dest_arn,
                    "destination_type": DestLogsType.REDSHIFT.value,
                    "destination_region": region
                    })
            elif FirehoseDestType.OPENSEARCH.value in destination:
                os_dest = destination[FirehoseDestType.OPENSEARCH.value]
                dest_arn = os_dest.get("DomainARN")
                results.append({
                    "destination_arn": dest_arn,
                    "destination_type": DestLogsType.OPENSEARCH.value,
                    "destination_region": region
                    })
            elif FirehoseDestType.ELASTICSEARCH.value in destination:
                es_dest = destination[FirehoseDestType.ELASTICSEARCH.value]
                dest_arn = es_dest.get("DomainARN")
                results.append({
                    "destination_arn": dest_arn,
                    "destination_type": DestLogsType.ELASTICSEARCH.value,
                    "destination_region": region
                    })
            else:
                results.append({
                    "destination_arn": firehose_arn,
                    "destination_type": DestLogsType.FIREHOSE.value,
                    "destination_region": region
                })
        return results

    except Exception as e:
        logger.warning(f"Failed to describe Firehose stream {stream_name}: {str(e)}")
        results.append({
                    "destination_arn": firehose_arn,
                    "destination_type": DestLogsType.FIREHOSE.value,
                    "destination_region": region
                })
        return results

def _resolve_log_destination_with_arn(sess, arn, region, account_id) -> list:
    results = []
    
    if ":logs:" in arn:
        arn_region = arn.split(":")[3] if ":" in arn else region
        results.append({
            "destination_arn": arn,
            "destination_type": DestLogsType.CWL.value,
            "destination_region": arn_region
        })
    elif ":s3:::" in arn:
        bucket_name = arn.split(":::")[1].split("/")[0]
        dest_region = _get_s3_bucket_region(sess, bucket_name) if bucket_name else None
        results.append({
            "destination_arn": arn,
            "destination_type": DestLogsType.S3.value,
            "destination_region": dest_region
        })
    elif ":firehose:" in arn:
        arn_region = arn.split(":")[3] if ":" in arn else region
        firehose_dests = _get_firehose_destination(sess, arn, arn_region)
        results.extend(firehose_dests)
    elif ":kinesis:" in arn:
        arn_region = arn.split(":")[3] if ":" in arn else region
        results.append({
            "destination_arn": arn,
            "destination_type": DestLogsType.KINESIS.value,
            "destination_region": arn_region
        })

    return results

def _resolve_log_destination_of_vpc(sess, log_config, region, account_id) -> list:
    results = []

    if not log_config:
        return results

    if "LogDestinationType" in log_config:
        log_dest_type = log_config.get("LogDestinationType")

        if log_dest_type == "cloud-watch-logs":
            log_group_name = log_config.get("LogGroupName")
            if log_group_name:
                dest_arn = f"arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}"
                results.append({
                    "destination_arn": dest_arn,
                    "destination_type": DestLogsType.CWL.value,
                    "destination_region": region
                })

        elif log_dest_type == "s3":
            dest_arn = log_config.get("LogDestination")
            if dest_arn and ":::" in dest_arn:
                bucket_name = dest_arn.split(":::")[1].split("/")[0]
                dest_region = _get_s3_bucket_region(sess, bucket_name) if bucket_name else None
                results.append({
                    "destination_arn": dest_arn,
                    "destination_type": DestLogsType.S3.value,
                    "destination_region": dest_region
                })

        elif log_dest_type == "kinesis-data-firehose":
            firehose_arn = log_config.get("LogDestination")
            if firehose_arn:
                arn_region = firehose_arn.split(":")[3] if ":" in firehose_arn else region
                firehose_dests = _get_firehose_destination(sess, firehose_arn, arn_region)
                results.extend(firehose_dests)

    return results

def _resolve_log_destination_of_waf(sess, log_config, region, account_id) -> list:
    results = []

    if not log_config:
        return results
    
    if "LogDestinationConfigs" in log_config:
        for dest_arn in log_config.get("LogDestinationConfigs", []):
            if ":s3:::" in dest_arn:
                bucket_name = dest_arn.split(":::")[1].split("/")[0]
                dest_region = _get_s3_bucket_region(sess, bucket_name) if bucket_name else None
                results.append({
                    "destination_arn": dest_arn,
                    "destination_type": DestLogsType.S3.value,
                    "destination_region": dest_region
                })
            elif ":firehose:" in dest_arn:
                arn_region = dest_arn.split(":")[3] if ":" in dest_arn else region
                firehose_dests = _get_firehose_destination(sess, dest_arn, arn_region)
                results.extend(firehose_dests)
            elif ":logs:" in dest_arn:
                arn_region = dest_arn.split(":")[3] if ":" in dest_arn else region
                results.append({
                    "destination_arn": dest_arn,
                    "destination_type": DestLogsType.CWL.value,
                    "destination_region": arn_region
                })
    
    return results

def _get_subscription_filter_destination(sess, log_group_name, region, account_id):
    cwl = sess.client("logs", region_name=region, config=RETRIES)
    results = []

    try:
        filters = cwl.describe_subscription_filters(logGroupName=log_group_name)

        if filters.get("subscriptionFilters"):
            for subscription_filter in filters["subscriptionFilters"]:
                subscription_dest_arn = subscription_filter.get("destinationArn")

                if ":firehose:" in subscription_dest_arn:
                    arn_region = subscription_dest_arn.split(":")[3] if ":" in subscription_dest_arn else region
                    firehose_dests = _get_firehose_destination(sess, subscription_dest_arn, arn_region)
                    results.extend(firehose_dests)

                elif ":kinesis:" in subscription_dest_arn:
                    arn_region = subscription_dest_arn.split(":")[3] if ":" in subscription_dest_arn else region
                    results.append({
                        "destination_arn": subscription_dest_arn,
                        "destination_type": DestLogsType.KINESIS.value,
                        "destination_region": arn_region
                    })

                # Lambda 또는 기타 목적지 (ARN 문자열로 전달)
                else:
                    destinations = _resolve_log_destination_with_arn(sess, subscription_dest_arn, region, account_id)
                    results.extend(destinations)

            return results
        else:
            return [{
                "destination_arn": f"arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}",
                "destination_type": DestLogsType.CWL.value,
                "destination_region": region
            }]
    except Exception as e:
        logger.warning(f"Failed to describe subscription filters for {log_group_name}: {str(e)}")
        return [{
            "destination_arn": f"arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}",
            "destination_type": DestLogsType.CWL.value,
            "destination_region": region
        }]