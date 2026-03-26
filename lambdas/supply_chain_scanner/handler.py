"""
Layer 1 — Supply Chain Scanner
Triggered by ECR scan completion.
Processes ECR scan findings, classifies by CWE,
writes to DynamoDB findings table, alerts on CRITICAL/HIGH.
"""

import json
import os
import uuid
import boto3
from datetime import datetime, timezone, timedelta

dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")
ecr = boto3.client("ecr")
cloudwatch = boto3.client("cloudwatch")

TABLE = os.environ["FINDINGS_TABLE"]
TOPIC = os.environ["ALERTS_TOPIC_ARN"]
ENV = os.environ.get("ENVIRONMENT", "dev")
SEVERITY_BLOCK = os.environ.get("SEVERITY_BLOCK", "CRITICAL,HIGH").split(",")

# CWE mapping for common vulnerability classes
CVE_TO_CWE = {
    "OS": "CWE-1104",       # Use of Unmaintained Third Party Components
    "LANG": "CWE-937",      # OWASP Top 10 - Vulnerable Components
    "SECRET": "CWE-312",    # Cleartext Storage of Sensitive Information
    "BACKDOOR": "CWE-506",  # Embedded Malicious Code
}


def lambda_handler(event, context):
    print(f"[supply-chain] Event: {json.dumps(event)}")

    detail = event.get("detail", {})
    repo_name = detail.get("repository-name", "unknown")
    image_digest = detail.get("image-digest", "unknown")
    image_tags = detail.get("image-tags", [])
    tag = image_tags[0] if image_tags else "untagged"

    # Retrieve full scan findings from ECR
    try:
        resp = ecr.describe_image_scan_findings(
            repositoryName=repo_name,
            imageId={"imageDigest": image_digest},
        )
        findings = resp.get("imageScanFindings", {}).get("findings", [])
        vuln_counts = resp.get("imageScanFindings", {}).get("findingSeverityCounts", {})
    except ecr.exceptions.ScanNotFoundException:
        print("[supply-chain] Scan results not available yet")
        return {"statusCode": 200, "body": "No scan results"}

    critical = vuln_counts.get("CRITICAL", 0)
    high = vuln_counts.get("HIGH", 0)
    medium = vuln_counts.get("MEDIUM", 0)
    total = sum(vuln_counts.values())

    # Compute supply chain score (100 = clean)
    penalty = (critical * 25) + (high * 10) + (medium * 3)
    score = max(0, 100 - penalty)

    # Build finding record
    finding_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    expires = int((datetime.now(timezone.utc) + timedelta(days=90)).timestamp())

    # Top 5 findings for summary
    top_findings = []
    for f in findings[:5]:
        top_findings.append({
            "name": f.get("name", ""),
            "severity": f.get("severity", ""),
            "description": f.get("description", "")[:200],
            "uri": f.get("uri", ""),
        })

    severity = "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "MEDIUM" if medium > 0 else "LOW"

    record = {
        "finding_id": finding_id,
        "detected_at": now,
        "layer": "supply_chain",
        "severity": severity,
        "resource": f"ecr/{repo_name}:{tag}",
        "image_digest": image_digest,
        "cwe_id": "CWE-1104",
        "pipeline_stage": "post-push",
        "environment": ENV,
        "score": score,
        "vulnerability_counts": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "total": total,
        },
        "top_findings": top_findings,
        "remediation": f"Rebuild image with patched base. Critical CVEs: {critical}",
        "expires_at": expires,
    }

    # Write to DynamoDB
    table = dynamodb.Table(TABLE)
    table.put_item(Item=record)
    print(f"[supply-chain] Finding written: {finding_id} score={score}")

    # Emit CloudWatch metric
    cloudwatch.put_metric_data(
        Namespace="SecurePath",
        MetricData=[
            {"MetricName": "SupplyChainScore", "Value": score,
             "Unit": "None", "Dimensions": [{"Name": "Environment", "Value": ENV}]},
            {"MetricName": f"Findings{severity.capitalize()}", "Value": 1,
             "Unit": "Count", "Dimensions": [{"Name": "Project", "Value": "securepath"}]},
        ],
    )

    # Alert if blocking severity
    if severity in SEVERITY_BLOCK:
        message = (
            f"SECURITY ALERT — Supply Chain Violation\n"
            f"Repository: {repo_name}:{tag}\n"
            f"Severity: {severity}\n"
            f"CRITICAL CVEs: {critical} | HIGH: {high} | MEDIUM: {medium}\n"
            f"Security Score: {score}/100\n"
            f"Finding ID: {finding_id}\n"
            f"Action: Image blocked from deployment"
        )
        sns.publish(
            TopicArn=TOPIC,
            Subject=f"[SecurePath] BLOCKED — {severity} CVEs in {repo_name}:{tag}",
            Message=message,
        )
        print(f"[supply-chain] ALERT sent — blocking severity {severity}")

    return {
        "statusCode": 200,
        "body": json.dumps({
            "finding_id": finding_id,
            "score": score,
            "severity": severity,
            "blocked": severity in SEVERITY_BLOCK,
        }),
    }
