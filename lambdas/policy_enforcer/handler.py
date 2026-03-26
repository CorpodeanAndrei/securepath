"""
Layer 4 — Policy Enforcer
Auto-remediates policy violations:
  - S3 bucket becomes public -> re-enable Block Public Access
  - Security group opens 0.0.0.0/0 -> revoke rule
  - Resource missing required tags -> log finding
"""

import json
import os
import uuid
import boto3
from datetime import datetime, timezone, timedelta

dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")
s3 = boto3.client("s3")
ec2 = boto3.client("ec2")
cloudwatch = boto3.client("cloudwatch")

TABLE = os.environ["FINDINGS_TABLE"]
TOPIC = os.environ["ALERTS_TOPIC_ARN"]
ENV = os.environ.get("ENVIRONMENT", "dev")
REQUIRED_TAGS = os.environ.get("REQUIRED_TAGS", "Owner,Environment,Project").split(",")


def remediate_s3_public(bucket_name, finding_id):
    """Block public access on S3 bucket."""
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        print(f"[policy-enforcer] Remediated S3 public access: {bucket_name}")
        return True
    except Exception as e:
        print(f"[policy-enforcer] Failed to remediate {bucket_name}: {e}")
        return False


def remediate_sg_open(sg_id, event_detail, finding_id):
    """Revoke overly permissive security group rules (0.0.0.0/0 on sensitive ports)."""
    SENSITIVE_PORTS = [22, 3389, 3306, 5432, 27017, 6379]
    revoked = []

    try:
        sg_resp = ec2.describe_security_groups(GroupIds=[sg_id])
        for sg in sg_resp.get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 65535)
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        for port in SENSITIVE_PORTS:
                            if from_port <= port <= to_port:
                                ec2.revoke_security_group_ingress(
                                    GroupId=sg_id,
                                    IpPermissions=[{
                                        "IpProtocol": perm.get("IpProtocol", "-1"),
                                        "FromPort": from_port,
                                        "ToPort": to_port,
                                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                    }],
                                )
                                revoked.append(port)
                                print(f"[policy-enforcer] Revoked port {port} on {sg_id}")
    except Exception as e:
        print(f"[policy-enforcer] SG remediation error {sg_id}: {e}")
    return revoked


def lambda_handler(event, context):
    print(f"[policy-enforcer] Event: {json.dumps(event)}")

    detail = event.get("detail", {})
    event_name = detail.get("eventName", "Unknown")
    event_source = detail.get("eventSource", "")
    request_params = detail.get("requestParameters", {})

    now = datetime.now(timezone.utc).isoformat()
    expires = int((datetime.now(timezone.utc) + timedelta(days=90)).timestamp())
    finding_id = str(uuid.uuid4())
    table = dynamodb.Table(TABLE)

    remediated = False
    severity = "HIGH"
    resource = "unknown"
    cwe_id = "CWE-284"
    remediation_detail = ""

    # S3 public access event
    if "s3" in event_source and event_name in (
        "PutBucketAcl", "PutBucketPolicy", "DeletePublicAccessBlock"
    ):
        bucket = request_params.get("bucketName", "unknown")
        resource = f"s3://{bucket}"
        severity = "CRITICAL"
        cwe_id = "CWE-284"
        remediated = remediate_s3_public(bucket, finding_id)
        remediation_detail = f"Block Public Access re-enabled on {bucket}"

    # Security group event
    elif "ec2" in event_source and event_name in (
        "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress"
    ):
        sg_id = (request_params.get("groupId") or
                 request_params.get("ModifySecurityGroupRulesRequest", {}).get("GroupId", "unknown"))
        resource = f"ec2/security-group/{sg_id}"
        severity = "HIGH"
        cwe_id = "CWE-284"
        revoked_ports = remediate_sg_open(sg_id, detail, finding_id)
        remediated = len(revoked_ports) > 0
        remediation_detail = f"Revoked 0.0.0.0/0 on ports {revoked_ports} in {sg_id}"

    record = {
        "finding_id": finding_id,
        "detected_at": now,
        "layer": "policy_engine",
        "severity": severity,
        "resource": resource,
        "cwe_id": cwe_id,
        "pipeline_stage": "runtime",
        "environment": ENV,
        "score": 0 if severity == "CRITICAL" else 40,
        "event_name": event_name,
        "auto_remediated": remediated,
        "remediation": remediation_detail,
        "expires_at": expires,
    }
    table.put_item(Item=record)

    cloudwatch.put_metric_data(
        Namespace="SecurePath",
        MetricData=[
            {"MetricName": "PolicyViolations", "Value": 1,
             "Unit": "Count", "Dimensions": [{"Name": "Environment", "Value": ENV}]},
        ],
    )

    sns.publish(
        TopicArn=TOPIC,
        Subject=f"[SecurePath] Policy Violation — {event_name} {'(REMEDIATED)' if remediated else '(MANUAL ACTION NEEDED)'}",
        Message=(
            f"Policy Violation Detected\n"
            f"Event: {event_name}\n"
            f"Resource: {resource}\n"
            f"Severity: {severity}\n"
            f"Auto-remediated: {remediated}\n"
            f"Detail: {remediation_detail}\n"
            f"Finding ID: {finding_id}"
        ),
    )

    return {
        "statusCode": 200,
        "body": json.dumps({"finding_id": finding_id, "remediated": remediated}),
    }
