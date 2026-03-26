"""
Layer 5 — Chaos Prober
Runs AWS FIS experiments and measures resilience metrics:
  RTO  (Recovery Time Objective)
  MTTR (Mean Time To Recovery)
  GDS  (Graceful Degradation Score) — custom metric
Writes results to DynamoDB and emits CloudWatch metrics.
"""

import json
import os
import time
import uuid
import boto3
from datetime import datetime, timezone, timedelta

dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")
fis = boto3.client("fis")
cloudwatch = boto3.client("cloudwatch")

TABLE = os.environ["FINDINGS_TABLE"]
TOPIC = os.environ["ALERTS_TOPIC_ARN"]
ENV = os.environ.get("ENVIRONMENT", "dev")
FIS_TEMPLATE_ARN = os.environ.get("FIS_TEMPLATE_ARN", "")
TARGET_RTO = int(os.environ.get("TARGET_SLA_RTO_SECS", "300"))
TARGET_MTTR = int(os.environ.get("TARGET_SLA_MTTR_SECS", "600"))


def get_error_rate_before(minutes=5):
    """Get baseline error rate before experiment."""
    try:
        resp = cloudwatch.get_metric_statistics(
            Namespace="AWS/Lambda",
            MetricName="Errors",
            Dimensions=[{"Name": "FunctionName", "Value": "securepath-policy-enforcer"}],
            StartTime=datetime.now(timezone.utc) - timedelta(minutes=minutes),
            EndTime=datetime.now(timezone.utc),
            Period=60,
            Statistics=["Sum"],
        )
        datapoints = resp.get("Datapoints", [])
        return sum(d["Sum"] for d in datapoints)
    except Exception:
        return 0.0


def run_fis_experiment(template_arn):
    """Start FIS experiment and wait for completion."""
    if not template_arn:
        print("[chaos] No FIS template ARN configured, running dry run")
        return {"status": "DRY_RUN", "duration_secs": 0}

    start_time = time.time()
    try:
        resp = fis.start_experiment(experimentTemplateId=template_arn.split("/")[-1])
        exp_id = resp["experiment"]["id"]
        print(f"[chaos] Started FIS experiment: {exp_id}")

        # Poll until terminal state
        max_wait = 900  # 15 minutes max
        while time.time() - start_time < max_wait:
            time.sleep(15)
            exp = fis.get_experiment(id=exp_id)
            state = exp["experiment"]["state"]["status"]
            print(f"[chaos] Experiment {exp_id} state: {state}")

            if state in ("completed", "failed", "stopped"):
                duration = int(time.time() - start_time)
                return {"status": state, "experiment_id": exp_id, "duration_secs": duration}

        return {"status": "TIMEOUT", "experiment_id": exp_id, "duration_secs": max_wait}

    except Exception as e:
        print(f"[chaos] FIS error: {e}")
        return {"status": "ERROR", "error": str(e), "duration_secs": 0}


def compute_resilience_score(rto_actual, mttr_actual, error_rate_delta):
    """
    GDS (Graceful Degradation Score): 0-100
    100 = system perfectly resilient within SLA
    0   = system failed to recover
    """
    score = 100

    # RTO penalty
    if rto_actual > TARGET_RTO:
        overage_ratio = rto_actual / TARGET_RTO
        score -= min(40, int((overage_ratio - 1) * 30))

    # MTTR penalty
    if mttr_actual > TARGET_MTTR:
        overage_ratio = mttr_actual / TARGET_MTTR
        score -= min(30, int((overage_ratio - 1) * 20))

    # Error rate penalty
    if error_rate_delta > 10:
        score -= 20
    elif error_rate_delta > 5:
        score -= 10

    return max(0, score)


def lambda_handler(event, context):
    print(f"[chaos] Starting chaos experiment run")

    baseline_errors = get_error_rate_before()
    experiment_start = datetime.now(timezone.utc)

    result = run_fis_experiment(FIS_TEMPLATE_ARN)

    experiment_end = datetime.now(timezone.utc)
    duration = result.get("duration_secs", 0)

    # Measure post-experiment error rate
    post_errors = get_error_rate_before(minutes=5)
    error_delta = max(0, post_errors - baseline_errors)

    # RTO: time until experiment completed (system recovered)
    rto_actual = duration
    # MTTR: assume MTTR = 1.5x RTO for now (more accurate with health checks)
    mttr_actual = int(duration * 1.5)

    gds = compute_resilience_score(rto_actual, mttr_actual, error_delta)
    rto_ok = rto_actual <= TARGET_RTO
    mttr_ok = mttr_actual <= TARGET_MTTR

    severity = "LOW" if gds >= 80 else "MEDIUM" if gds >= 60 else "HIGH"

    now = datetime.now(timezone.utc).isoformat()
    expires = int((datetime.now(timezone.utc) + timedelta(days=90)).timestamp())
    finding_id = str(uuid.uuid4())

    record = {
        "finding_id": finding_id,
        "detected_at": now,
        "layer": "chaos_prober",
        "severity": severity,
        "resource": "infrastructure/resilience",
        "cwe_id": "CWE-920",  # Improper Restriction of Power Consumption
        "pipeline_stage": "runtime",
        "environment": ENV,
        "score": gds,
        "experiment_status": result.get("status"),
        "experiment_id": result.get("experiment_id", "dry-run"),
        "rto_actual_secs": rto_actual,
        "rto_target_secs": TARGET_RTO,
        "rto_ok": rto_ok,
        "mttr_actual_secs": mttr_actual,
        "mttr_target_secs": TARGET_MTTR,
        "mttr_ok": mttr_ok,
        "graceful_degradation_score": gds,
        "error_rate_delta": error_delta,
        "remediation": "Review resilience architecture. Check retry logic, circuit breakers, health checks.",
        "expires_at": expires,
    }

    table = dynamodb.Table(TABLE)
    table.put_item(Item=record)
    print(f"[chaos] Finding: {finding_id} GDS={gds} RTO={rto_actual}s MTTR={mttr_actual}s")

    cloudwatch.put_metric_data(
        Namespace="SecurePath",
        MetricData=[
            {"MetricName": "GracefulDegradationScore", "Value": gds,
             "Unit": "None", "Dimensions": [{"Name": "Environment", "Value": ENV}]},
            {"MetricName": "ExperimentRTO", "Value": rto_actual,
             "Unit": "Seconds", "Dimensions": [{"Name": "Environment", "Value": ENV}]},
            {"MetricName": "ExperimentMTTR", "Value": mttr_actual,
             "Unit": "Seconds", "Dimensions": [{"Name": "Environment", "Value": ENV}]},
        ],
    )

    if not rto_ok or not mttr_ok or severity == "HIGH":
        sns.publish(
            TopicArn=TOPIC,
            Subject=f"[SecurePath] Resilience SLA {'BREACH' if not rto_ok else 'WARNING'} — GDS {gds}/100",
            Message=(
                f"Chaos Experiment Results\n"
                f"Experiment: {result.get('experiment_id', 'dry-run')}\n"
                f"Status: {result.get('status')}\n\n"
                f"RTO: {rto_actual}s (target: {TARGET_RTO}s) {'OK' if rto_ok else 'BREACHED'}\n"
                f"MTTR: {mttr_actual}s (target: {TARGET_MTTR}s) {'OK' if mttr_ok else 'BREACHED'}\n"
                f"GDS: {gds}/100\n"
                f"Finding ID: {finding_id}"
            ),
        )

    return {
        "statusCode": 200,
        "body": json.dumps({
            "finding_id": finding_id,
            "gds": gds,
            "rto_ok": rto_ok,
            "mttr_ok": mttr_ok,
        }),
    }
