"""
Layer 3 — Infrastructure Drift Detector
Triggered by AWS Config rule violations and on schedule.
Compares actual resource state vs expected (Config rules baseline).
Classifies drift severity and initiates remediation.
"""

import json
import os
import uuid
import boto3
from datetime import datetime, timezone, timedelta

dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")
config = boto3.client("config")
cloudwatch = boto3.client("cloudwatch")

TABLE = os.environ["FINDINGS_TABLE"]
TOPIC = os.environ["ALERTS_TOPIC_ARN"]
ENV = os.environ.get("ENVIRONMENT", "dev")

# Drift classification: rule name -> (severity, drift_type, cwe_id)
RULE_CLASSIFICATION = {
    "securepath-s3-no-public-access": ("CRITICAL", "security_drift", "CWE-284"),
    "securepath-ec2-encrypted-volumes": ("HIGH", "security_drift", "CWE-311"),
    "securepath-no-root-access-key": ("CRITICAL", "security_drift", "CWE-250"),
    "securepath-rds-encrypted": ("HIGH", "security_drift", "CWE-311"),
}


def get_noncompliant_resources(rule_name):
    """Retrieve all non-compliant resources for a Config rule."""
    resources = []
    paginator = config.get_paginator("get_compliance_details_by_config_rule")
    for page in paginator.paginate(
        ConfigRuleName=rule_name,
        ComplianceTypes=["NON_COMPLIANT"]
    ):
        resources.extend(page.get("EvaluationResults", []))
    return resources


def lambda_handler(event, context):
    print(f"[drift-detector] Event type: {event.get('detail-type', 'schedule')}")

    now = datetime.now(timezone.utc).isoformat()
    expires = int((datetime.now(timezone.utc) + timedelta(days=90)).timestamp())
    table = dynamodb.Table(TABLE)

    # Get all Config rules to check
    rules_response = config.describe_config_rules()
    rules = rules_response.get("ConfigRules", [])

    total_drifts = 0
    critical_drifts = 0

    for rule in rules:
        rule_name = rule["ConfigRuleName"]
        if not rule_name.startswith("securepath-"):
            continue

        noncompliant = get_noncompliant_resources(rule_name)
        if not noncompliant:
            continue

        classification = RULE_CLASSIFICATION.get(
            rule_name, ("MEDIUM", "configuration_drift", "CWE-16")
        )
        severity, drift_type, cwe_id = classification

        for resource in noncompliant:
            qi = resource.get("EvaluationResultIdentifier", {}).get(
                "EvaluationResultQualifier", {}
            )
            resource_id = qi.get("ResourceId", "unknown")
            resource_type = qi.get("ResourceType", "unknown")

            finding_id = str(uuid.uuid4())
            record = {
                "finding_id": finding_id,
                "detected_at": now,
                "layer": "drift_detector",
                "severity": severity,
                "resource": f"{resource_type}/{resource_id}",
                "cwe_id": cwe_id,
                "pipeline_stage": "runtime",
                "environment": ENV,
                "score": 0 if severity == "CRITICAL" else 40 if severity == "HIGH" else 70,
                "config_rule": rule_name,
                "drift_type": drift_type,
                "remediation": f"Re-apply Terraform for {resource_type}/{resource_id} to restore desired state",
                "auto_remediated": False,
                "expires_at": expires,
            }
            table.put_item(Item=record)
            total_drifts += 1
            if severity == "CRITICAL":
                critical_drifts += 1
            print(f"[drift-detector] Drift: {finding_id} {rule_name} -> {resource_id} [{severity}]")

    # Metrics
    cloudwatch.put_metric_data(
        Namespace="SecurePath",
        MetricData=[
            {"MetricName": "DriftDetected", "Value": total_drifts,
             "Unit": "Count", "Dimensions": [{"Name": "Project", "Value": "securepath"}]},
        ],
    )

    # Alert on critical drifts
    if critical_drifts > 0:
        sns.publish(
            TopicArn=TOPIC,
            Subject=f"[SecurePath] CRITICAL Infrastructure Drift Detected ({critical_drifts} resources)",
            Message=(
                f"Infrastructure Drift Alert\n"
                f"Critical drifts: {critical_drifts}\n"
                f"Total drifts: {total_drifts}\n"
                f"Environment: {ENV}\n"
                f"Action required: Run terraform plan to review and terraform apply to remediate\n"
                f"Detected at: {now}"
            ),
        )

    return {
        "statusCode": 200,
        "body": json.dumps({"total_drifts": total_drifts, "critical_drifts": critical_drifts}),
    }
