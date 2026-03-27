import boto3
import uuid
import json
from datetime import datetime, timezone, timedelta

db = boto3.resource("dynamodb", region_name="eu-west-1")
table = db.Table("securepath-findings")
now = datetime.now(timezone.utc)
exp = int((now + timedelta(days=90)).timestamp())

findings = [
    # Layer 1 - Supply Chain
    {
        "finding_id": str(uuid.uuid4()),
        "detected_at": now.isoformat(),
        "layer": "supply_chain",
        "severity": "CRITICAL",
        "resource": "ecr/securepath-app:python36-vuln",
        "cwe_id": "CWE-120",
        "pipeline_stage": "post-push",
        "environment": "dev",
        "score": 0,
        "auto_remediated": False,
        "vulnerability_counts": json.dumps({"critical": 3, "high": 12, "medium": 18, "total": 33}),
        "remediation": "Upgrade to python:3.12. CVE-2021-3177 buffer overflow, CVE-2022-0391 url parsing, CVE-2021-23336 web cache poisoning",
        "expires_at": exp,
    },
    {
        "finding_id": str(uuid.uuid4()),
        "detected_at": (now - timedelta(minutes=10)).isoformat(),
        "layer": "supply_chain",
        "severity": "HIGH",
        "resource": "ecr/securepath-app:python36-vuln",
        "cwe_id": "CWE-937",
        "pipeline_stage": "post-push",
        "environment": "dev",
        "score": 30,
        "auto_remediated": False,
        "vulnerability_counts": json.dumps({"critical": 0, "high": 12, "medium": 18, "total": 30}),
        "remediation": "Update base image dependencies",
        "expires_at": exp,
    },
    # Layer 2 - IAM Zero Trust
    {
        "finding_id": str(uuid.uuid4()),
        "detected_at": (now - timedelta(minutes=30)).isoformat(),
        "layer": "iam_zero_trust",
        "severity": "CRITICAL",
        "resource": "iam/securepath-attack-test2",
        "cwe_id": "CWE-266",
        "pipeline_stage": "runtime",
        "environment": "dev",
        "score": 10,
        "auto_remediated": False,
        "blast_radius": 95,
        "zero_trust_score": 10,
        "event_name": "AttachRolePolicy",
        "expires_at": exp,
    },
    {
        "finding_id": str(uuid.uuid4()),
        "detected_at": (now - timedelta(minutes=25)).isoformat(),
        "layer": "iam_zero_trust",
        "severity": "HIGH",
        "resource": "iam/securepath-lambda-exec",
        "cwe_id": "CWE-266",
        "pipeline_stage": "runtime",
        "environment": "dev",
        "score": 45,
        "auto_remediated": False,
        "blast_radius": 55,
        "zero_trust_score": 45,
        "event_name": "PutRolePolicy",
        "expires_at": exp,
    },
    # Layer 3 - Drift Detector
    {
        "finding_id": str(uuid.uuid4()),
        "detected_at": (now - timedelta(hours=1)).isoformat(),
        "layer": "drift_detector",
        "severity": "CRITICAL",
        "resource": "AWS::S3::Bucket/securepath-config-dev",
        "cwe_id": "CWE-311",
        "pipeline_stage": "runtime",
        "environment": "dev",
        "score": 0,
        "auto_remediated": True,
        "drift_type": "security_drift",
        "config_rule": "securepath-s3-no-public-access",
        "expires_at": exp,
    },
    {
        "finding_id": str(uuid.uuid4()),
        "detected_at": (now - timedelta(minutes=50)).isoformat(),
        "layer": "drift_detector",
        "severity": "HIGH",
        "resource": "AWS::EC2::Volume/vol-0abc123def",
        "cwe_id": "CWE-311",
        "pipeline_stage": "runtime",
        "environment": "dev",
        "score": 40,
        "auto_remediated": False,
        "drift_type": "security_drift",
        "config_rule": "securepath-ec2-encrypted-volumes",
        "expires_at": exp,
    },
    # Layer 4 - Policy Engine
    {
        "finding_id": str(uuid.uuid4()),
        "detected_at": (now - timedelta(minutes=20)).isoformat(),
        "layer": "policy_engine",
        "severity": "CRITICAL",
        "resource": "s3://securepath-config-dev",
        "cwe_id": "CWE-284",
        "pipeline_stage": "runtime",
        "environment": "dev",
        "score": 0,
        "auto_remediated": True,
        "event_name": "DeletePublicAccessBlock",
        "expires_at": exp,
    },
    {
        "finding_id": str(uuid.uuid4()),
        "detected_at": (now - timedelta(minutes=15)).isoformat(),
        "layer": "policy_engine",
        "severity": "HIGH",
        "resource": "ec2/security-group/sg-0a15dfa1426c7d83a",
        "cwe_id": "CWE-284",
        "pipeline_stage": "runtime",
        "environment": "dev",
        "score": 40,
        "auto_remediated": True,
        "event_name": "AuthorizeSecurityGroupIngress",
        "expires_at": exp,
    },
    # Layer 5 - Chaos Prober
    {
        "finding_id": str(uuid.uuid4()),
        "detected_at": (now - timedelta(hours=4)).isoformat(),
        "layer": "chaos_prober",
        "severity": "MEDIUM",
        "resource": "infrastructure/resilience",
        "cwe_id": "CWE-920",
        "pipeline_stage": "runtime",
        "environment": "dev",
        "score": 72,
        "auto_remediated": False,
        "rto_actual_secs": 280,
        "rto_target_secs": 300,
        "mttr_actual_secs": 420,
        "mttr_target_secs": 600,
        "graceful_degradation_score": 72,
        "expires_at": exp,
    },
]

for f in findings:
    table.put_item(Item=f)
    print("[OK] {:<22} {}".format(f["layer"], f["severity"]))

print("Total: {} findings injectate.".format(len(findings)))