"""
Layer 2 — IAM Graph Analyzer (Zero-Trust)
Triggered by IAM mutation events via CloudTrail.
Builds a simplified IAM graph, computes blast radius,
calculates Zero-Trust Score per principal.
"""

import json
import os
import uuid
import boto3
from datetime import datetime, timezone, timedelta

dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")
iam = boto3.client("iam")
cloudwatch = boto3.client("cloudwatch")

TABLE = os.environ["FINDINGS_TABLE"]
TOPIC = os.environ["ALERTS_TOPIC_ARN"]
ENV = os.environ.get("ENVIRONMENT", "dev")
ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "")

# Dangerous permissions that increase blast radius significantly
BLAST_AMPLIFIERS = {
    "iam:*": 30,
    "sts:AssumeRole": 20,
    "s3:*": 15,
    "ec2:*": 15,
    "lambda:*": 10,
    "*": 50,
    "iam:PassRole": 25,
    "iam:CreatePolicyVersion": 20,
}


def get_role_policies(role_name):
    """Retrieve all policy documents for a role (inline + attached)."""
    permissions = set()
    try:
        # Inline policies
        inline = iam.list_role_policies(RoleName=role_name)
        for pname in inline.get("PolicyNames", []):
            doc = iam.get_role_policy(RoleName=role_name, PolicyName=pname)
            for stmt in doc["PolicyDocument"].get("Statement", []):
                if stmt.get("Effect") == "Allow":
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    permissions.update(actions)

        # Attached managed policies
        attached = iam.list_attached_role_policies(RoleName=role_name)
        for policy in attached.get("AttachedPolicies", []):
            pv = iam.get_policy(PolicyArn=policy["PolicyArn"])
            version_id = pv["Policy"]["DefaultVersionId"]
            pv_doc = iam.get_policy_version(
                PolicyArn=policy["PolicyArn"], VersionId=version_id
            )
            for stmt in pv_doc["PolicyVersion"]["Document"].get("Statement", []):
                if stmt.get("Effect") == "Allow":
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    permissions.update(actions)
    except Exception as e:
        print(f"[iam-graph] Error getting policies for {role_name}: {e}")
    return permissions


def compute_blast_radius(permissions):
    """Score 0-100: how much damage if this principal is compromised."""
    score = 0
    for perm in permissions:
        for amplifier, weight in BLAST_AMPLIFIERS.items():
            if amplifier == perm or (amplifier.endswith(":*") and
                                     perm.startswith(amplifier[:-1])):
                score += weight
    return min(100, score)


def compute_zero_trust_score(permissions, blast_radius):
    """Zero-Trust Score 0-100: higher = more compliant."""
    score = 100

    # Penalize for overly broad permissions
    if "*" in permissions:
        score -= 40
    if "iam:*" in permissions:
        score -= 25
    if blast_radius > 50:
        score -= 20
    elif blast_radius > 25:
        score -= 10

    # Penalize for privilege escalation vectors
    escalation_perms = {"iam:PassRole", "iam:CreatePolicyVersion",
                        "sts:AssumeRole", "iam:AttachRolePolicy"}
    overlap = len(permissions & escalation_perms)
    score -= overlap * 8

    return max(0, score)


def lambda_handler(event, context):
    print(f"[iam-graph] Event: {json.dumps(event)}")

    detail = event.get("detail", {})
    event_name = detail.get("eventName", "Unknown")
    principal = detail.get("userIdentity", {}).get("arn", "unknown")
    request_params = detail.get("requestParameters", {})

    # Extract affected role name if applicable
    role_name = (
        request_params.get("roleName") or
        request_params.get("userName") or
        "unknown"
    )

    now = datetime.now(timezone.utc).isoformat()
    expires = int((datetime.now(timezone.utc) + timedelta(days=90)).timestamp())
    finding_id = str(uuid.uuid4())

    blast_radius = 0
    zt_score = 100
    permissions = set()

    if role_name != "unknown" and request_params.get("roleName"):
        permissions = get_role_policies(role_name)
        blast_radius = compute_blast_radius(permissions)
        zt_score = compute_zero_trust_score(permissions, blast_radius)

    severity = "LOW"
    if zt_score < 40 or blast_radius > 60:
        severity = "CRITICAL"
    elif zt_score < 60 or blast_radius > 40:
        severity = "HIGH"
    elif zt_score < 75 or blast_radius > 20:
        severity = "MEDIUM"

    record = {
        "finding_id": finding_id,
        "detected_at": now,
        "layer": "iam_zero_trust",
        "severity": severity,
        "resource": f"iam/{role_name}",
        "cwe_id": "CWE-266",  # Incorrect Privilege Assignment
        "pipeline_stage": "runtime",
        "environment": ENV,
        "score": zt_score,
        "event_name": event_name,
        "principal_arn": principal,
        "blast_radius": blast_radius,
        "zero_trust_score": zt_score,
        "dangerous_permissions": list(permissions & set(BLAST_AMPLIFIERS.keys())),
        "remediation": f"Review role {role_name}. Blast radius: {blast_radius}/100. Apply least-privilege.",
        "expires_at": expires,
    }

    table = dynamodb.Table(TABLE)
    table.put_item(Item=record)
    print(f"[iam-graph] Finding: {finding_id} zt_score={zt_score} blast={blast_radius}")

    cloudwatch.put_metric_data(
        Namespace="SecurePath",
        MetricData=[
            {"MetricName": "ZeroTrustScore", "Value": zt_score,
             "Unit": "None", "Dimensions": [{"Name": "Role", "Value": role_name}]},
            {"MetricName": "IamMutationCount", "Value": 1,
             "Unit": "Count", "Dimensions": [{"Name": "Environment", "Value": ENV}]},
        ],
    )

    if severity in ("CRITICAL", "HIGH"):
        sns.publish(
            TopicArn=TOPIC,
            Subject=f"[SecurePath] IAM {severity} — {event_name} on {role_name}",
            Message=(
                f"IAM Security Alert\n"
                f"Event: {event_name}\n"
                f"Role: {role_name}\n"
                f"Triggered by: {principal}\n"
                f"Zero-Trust Score: {zt_score}/100\n"
                f"Blast Radius: {blast_radius}/100\n"
                f"Dangerous permissions: {list(permissions & set(BLAST_AMPLIFIERS.keys()))}\n"
                f"Finding ID: {finding_id}"
            ),
        )

    return {"statusCode": 200,
            "body": json.dumps({"finding_id": finding_id, "zt_score": zt_score})}
