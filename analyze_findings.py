"""
SecurePath — Academic Data Collection & Analysis Script
========================================================
Extrage findings din DynamoDB, calculeaza CSPS per layer,
genereaza CSV si grafice pentru articolul academic.

Instalare dependinte:
    pip install boto3 pandas matplotlib seaborn scipy

Rulare:
    python analyze_findings.py --region eu-west-1
    python analyze_findings.py --region eu-west-1 --inject-demo
"""

import argparse
import json
import uuid
import csv
import os
from datetime import datetime, timezone, timedelta
from collections import defaultdict

# ---------------------------------------------------------------
# IMPORTS — cu fallback daca lipsesc pachete optionale
# ---------------------------------------------------------------
try:
    import boto3
    from boto3.dynamodb.conditions import Attr
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False
    print("[WARN] boto3 nu e instalat. Ruleaza: pip install boto3")

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False
    print("[WARN] pandas nu e instalat. Ruleaza: pip install pandas")

try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("[WARN] matplotlib nu e instalat. Ruleaza: pip install matplotlib")

try:
    import seaborn as sns
    HAS_SEABORN = True
except ImportError:
    HAS_SEABORN = False

try:
    from scipy import stats
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False
    print("[WARN] scipy nu e instalat. Ruleaza: pip install scipy")

# ---------------------------------------------------------------
# CONFIGURARE
# ---------------------------------------------------------------
TABLE_NAME = "securepath-findings"

LAYER_LABELS = {
    "supply_chain":  "L1: Supply Chain",
    "iam_zero_trust": "L2: Zero-Trust IAM",
    "drift_detector": "L3: Drift Detector",
    "policy_engine":  "L4: Policy Engine",
    "chaos_prober":   "L5: Chaos Prober",
}

LAYER_COLORS = {
    "supply_chain":   "#E8593C",
    "iam_zero_trust": "#534AB7",
    "drift_detector": "#0F6E56",
    "policy_engine":  "#BA7517",
    "chaos_prober":   "#185FA5",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_COLORS = {
    "CRITICAL": "#A32D2D",
    "HIGH":     "#E24B4A",
    "MEDIUM":   "#BA7517",
    "LOW":      "#3B6D11",
    "INFO":     "#185FA5",
}

# CSPS weights per layer (calibrate pe baza literaturii de securitate)
CSPS_WEIGHTS = {
    "supply_chain":   0.25,
    "iam_zero_trust": 0.30,
    "drift_detector": 0.20,
    "policy_engine":  0.15,
    "chaos_prober":   0.10,
}

# ---------------------------------------------------------------
# DATE DEMO — pentru testare fara findings reale in DynamoDB
# ---------------------------------------------------------------
DEMO_FINDINGS = [
    # Layer 1 — Supply Chain
    {
        "finding_id": {"S": str(uuid.uuid4())},
        "detected_at": {"S": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()},
        "layer": {"S": "supply_chain"},
        "severity": {"S": "CRITICAL"},
        "resource": {"S": "ecr/securepath-app:test-vuln"},
        "cwe_id": {"S": "CWE-1104"},
        "pipeline_stage": {"S": "post-push"},
        "environment": {"S": "dev"},
        "score": {"N": "15"},
        "auto_remediated": {"BOOL": False},
        "vulnerability_counts": {"S": '{"critical":3,"high":8,"medium":12,"total":23}'},
    },
    {
        "finding_id": {"S": str(uuid.uuid4())},
        "detected_at": {"S": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()},
        "layer": {"S": "supply_chain"},
        "severity": {"S": "HIGH"},
        "resource": {"S": "ecr/securepath-app:v1.0"},
        "cwe_id": {"S": "CWE-937"},
        "pipeline_stage": {"S": "post-push"},
        "environment": {"S": "dev"},
        "score": {"N": "52"},
        "auto_remediated": {"BOOL": False},
        "vulnerability_counts": {"S": '{"critical":0,"high":4,"medium":6,"total":10}'},
    },
    # Layer 2 — IAM Zero Trust
    {
        "finding_id": {"S": str(uuid.uuid4())},
        "detected_at": {"S": (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()},
        "layer": {"S": "iam_zero_trust"},
        "severity": {"S": "CRITICAL"},
        "resource": {"S": "iam/securepath-attack-test2"},
        "cwe_id": {"S": "CWE-266"},
        "pipeline_stage": {"S": "runtime"},
        "environment": {"S": "dev"},
        "score": {"N": "10"},
        "blast_radius": {"N": "95"},
        "zero_trust_score": {"N": "10"},
        "auto_remediated": {"BOOL": False},
        "event_name": {"S": "AttachRolePolicy"},
    },
    {
        "finding_id": {"S": str(uuid.uuid4())},
        "detected_at": {"S": (datetime.now(timezone.utc) - timedelta(minutes=45)).isoformat()},
        "layer": {"S": "iam_zero_trust"},
        "severity": {"S": "HIGH"},
        "resource": {"S": "iam/securepath-lambda-exec"},
        "cwe_id": {"S": "CWE-266"},
        "pipeline_stage": {"S": "runtime"},
        "environment": {"S": "dev"},
        "score": {"N": "45"},
        "blast_radius": {"N": "55"},
        "zero_trust_score": {"N": "45"},
        "auto_remediated": {"BOOL": False},
        "event_name": {"S": "PutRolePolicy"},
    },
    # Layer 3 — Drift Detector
    {
        "finding_id": {"S": str(uuid.uuid4())},
        "detected_at": {"S": (datetime.now(timezone.utc) - timedelta(hours=1, minutes=30)).isoformat()},
        "layer": {"S": "drift_detector"},
        "severity": {"S": "CRITICAL"},
        "resource": {"S": "AWS::S3::Bucket/securepath-config-dev"},
        "cwe_id": {"S": "CWE-311"},
        "pipeline_stage": {"S": "runtime"},
        "environment": {"S": "dev"},
        "score": {"N": "0"},
        "drift_type": {"S": "security_drift"},
        "config_rule": {"S": "securepath-s3-no-public-access"},
        "auto_remediated": {"BOOL": True},
    },
    {
        "finding_id": {"S": str(uuid.uuid4())},
        "detected_at": {"S": (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()},
        "layer": {"S": "drift_detector"},
        "severity": {"S": "HIGH"},
        "resource": {"S": "AWS::EC2::Volume/vol-0abc123"},
        "cwe_id": {"S": "CWE-311"},
        "pipeline_stage": {"S": "runtime"},
        "environment": {"S": "dev"},
        "score": {"N": "40"},
        "drift_type": {"S": "security_drift"},
        "config_rule": {"S": "securepath-ec2-encrypted-volumes"},
        "auto_remediated": {"BOOL": False},
    },
    # Layer 4 — Policy Engine
    {
        "finding_id": {"S": str(uuid.uuid4())},
        "detected_at": {"S": (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()},
        "layer": {"S": "policy_engine"},
        "severity": {"S": "HIGH"},
        "resource": {"S": "ec2/security-group/sg-0a15dfa1426c7d83a"},
        "cwe_id": {"S": "CWE-284"},
        "pipeline_stage": {"S": "runtime"},
        "environment": {"S": "dev"},
        "score": {"N": "40"},
        "event_name": {"S": "AuthorizeSecurityGroupIngress"},
        "auto_remediated": {"BOOL": True},
    },
    {
        "finding_id": {"S": str(uuid.uuid4())},
        "detected_at": {"S": (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()},
        "layer": {"S": "policy_engine"},
        "severity": {"S": "CRITICAL"},
        "resource": {"S": "s3://test-public-bucket"},
        "cwe_id": {"S": "CWE-284"},
        "pipeline_stage": {"S": "runtime"},
        "environment": {"S": "dev"},
        "score": {"N": "0"},
        "event_name": {"S": "DeletePublicAccessBlock"},
        "auto_remediated": {"BOOL": True},
    },
    # Layer 5 — Chaos Prober
    {
        "finding_id": {"S": str(uuid.uuid4())},
        "detected_at": {"S": (datetime.now(timezone.utc) - timedelta(hours=4)).isoformat()},
        "layer": {"S": "chaos_prober"},
        "severity": {"S": "MEDIUM"},
        "resource": {"S": "infrastructure/resilience"},
        "cwe_id": {"S": "CWE-920"},
        "pipeline_stage": {"S": "runtime"},
        "environment": {"S": "dev"},
        "score": {"N": "72"},
        "rto_actual_secs": {"N": "280"},
        "rto_target_secs": {"N": "300"},
        "mttr_actual_secs": {"N": "420"},
        "mttr_target_secs": {"N": "600"},
        "graceful_degradation_score": {"N": "72"},
        "auto_remediated": {"BOOL": False},
    },
]


# ---------------------------------------------------------------
# FUNCTII PRINCIPALE
# ---------------------------------------------------------------

def fetch_findings(region: str) -> list:
    """Extrage toate findings din DynamoDB."""
    if not HAS_BOTO3:
        return []

    dynamodb = boto3.resource("dynamodb", region_name=region)
    table = dynamodb.Table(TABLE_NAME)

    items = []
    response = table.scan()
    items.extend(response.get("Items", []))

    while "LastEvaluatedKey" in response:
        response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
        items.extend(response.get("Items", []))

    return items


def normalize_item(item: dict) -> dict:
    """Normalizeaza un item DynamoDB (poate fi raw sau deja deserializat)."""
    def get_val(field, typ="S", default=None):
        v = item.get(field, {})
        if isinstance(v, dict):
            return v.get(typ, default)
        return v if v is not None else default

    return {
        "finding_id":     get_val("finding_id"),
        "detected_at":    get_val("detected_at"),
        "layer":          get_val("layer"),
        "severity":       get_val("severity"),
        "resource":       get_val("resource"),
        "cwe_id":         get_val("cwe_id"),
        "pipeline_stage": get_val("pipeline_stage"),
        "environment":    get_val("environment"),
        "score":          float(get_val("score", "N", 50) or 50),
        "auto_remediated": item.get("auto_remediated", {}).get("BOOL", False)
                           if isinstance(item.get("auto_remediated"), dict)
                           else bool(item.get("auto_remediated", False)),
        "blast_radius":   float(get_val("blast_radius", "N", 0) or 0),
        "rto_actual_secs": float(get_val("rto_actual_secs", "N", 0) or 0),
        "mttr_actual_secs": float(get_val("mttr_actual_secs", "N", 0) or 0),
        "gds":            float(get_val("graceful_degradation_score", "N", 0) or 0),
    }


def compute_csps(findings: list) -> dict:
    """
    Calculeaza Cloud Security Posture Score (CSPS) agregat.
    Formula: suma ponderata a scorurilor medii per layer.
    """
    layer_scores = defaultdict(list)
    for f in findings:
        layer_scores[f["layer"]].append(f["score"])

    weighted_sum = 0.0
    total_weight = 0.0
    breakdown = {}

    for layer, weight in CSPS_WEIGHTS.items():
        scores = layer_scores.get(layer, [])
        if scores:
            avg = sum(scores) / len(scores)
        else:
            avg = 100.0  # fara findings = perfect
        breakdown[layer] = round(avg, 1)
        weighted_sum += avg * weight
        total_weight += weight

    csps = weighted_sum / total_weight if total_weight > 0 else 100.0
    return {"csps": round(csps, 1), "breakdown": breakdown}


def compute_statistics(findings: list) -> dict:
    """Statistici descriptive pentru articol."""
    total = len(findings)
    if total == 0:
        return {}

    by_severity = defaultdict(int)
    by_layer = defaultdict(int)
    remediated = 0
    scores = []

    for f in findings:
        by_severity[f["severity"]] += 1
        by_layer[f["layer"]] += 1
        if f["auto_remediated"]:
            remediated += 1
        scores.append(f["score"])

    remediation_rate = (remediated / total * 100) if total > 0 else 0

    stats_out = {
        "total_findings": total,
        "by_severity": dict(by_severity),
        "by_layer": dict(by_layer),
        "auto_remediation_rate_pct": round(remediation_rate, 1),
        "score_mean": round(sum(scores) / len(scores), 1),
        "score_min": min(scores),
        "score_max": max(scores),
    }

    if HAS_SCIPY and len(scores) > 1:
        stats_out["score_std"] = round(float(stats.tstd(scores)), 1)
        stats_out["score_median"] = round(float(stats.scoreatpercentile(scores, 50)), 1)

    return stats_out


def export_csv(findings: list, output_dir: str):
    """Exporta findings in CSV pentru analiza in Excel/R/SPSS."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "securepath_findings.csv")

    fieldnames = [
        "finding_id", "detected_at", "layer", "severity",
        "resource", "cwe_id", "pipeline_stage", "environment",
        "score", "auto_remediated", "blast_radius",
        "rto_actual_secs", "mttr_actual_secs", "gds",
    ]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(findings)

    print(f"[OK] CSV exportat: {path}")
    return path


def export_summary_json(stats: dict, csps: dict, output_dir: str):
    """Exporta rezumatul statistic in JSON."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "securepath_summary.json")

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "csps": csps,
        "statistics": stats,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"[OK] Summary JSON exportat: {path}")
    return path


# ---------------------------------------------------------------
# GRAFICE
# ---------------------------------------------------------------

def plot_severity_distribution(findings: list, output_dir: str):
    """Grafic 1 — Distributia findings pe severitate per layer."""
    if not HAS_MATPLOTLIB:
        return

    layers = list(LAYER_LABELS.keys())
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    data = {sev: [] for sev in severities}
    for layer in layers:
        layer_findings = [f for f in findings if f["layer"] == layer]
        for sev in severities:
            count = sum(1 for f in layer_findings if f["severity"] == sev)
            data[sev].append(count)

    fig, ax = plt.subplots(figsize=(10, 6))
    x = range(len(layers))
    width = 0.2
    offsets = [-1.5, -0.5, 0.5, 1.5]

    for i, sev in enumerate(severities):
        bars = ax.bar(
            [xi + offsets[i] * width for xi in x],
            data[sev],
            width,
            label=sev,
            color=SEVERITY_COLORS[sev],
            alpha=0.85,
        )

    ax.set_xlabel("Security Layer", fontsize=12)
    ax.set_ylabel("Number of Findings", fontsize=12)
    ax.set_title("Finding Distribution by Severity per Security Layer", fontsize=13)
    ax.set_xticks(list(x))
    ax.set_xticklabels([LAYER_LABELS[l] for l in layers], rotation=15, ha="right")
    ax.legend(title="Severity")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()

    path = os.path.join(output_dir, "fig1_severity_distribution.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Figura 1 salvata: {path}")


def plot_csps_radar(csps: dict, output_dir: str):
    """Grafic 2 — CSPS breakdown per layer (bar chart)."""
    if not HAS_MATPLOTLIB:
        return

    layers = list(LAYER_LABELS.keys())
    scores = [csps["breakdown"].get(l, 100) for l in layers]
    colors = [LAYER_COLORS[l] for l in layers]

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.barh(
        [LAYER_LABELS[l] for l in layers],
        scores,
        color=colors,
        alpha=0.85,
    )

    # Adauga valori pe bare
    for bar, score in zip(bars, scores):
        ax.text(
            bar.get_width() + 1, bar.get_y() + bar.get_height() / 2,
            f"{score:.1f}", va="center", fontsize=10,
        )

    # Linie CSPS total
    csps_total = csps["csps"]
    ax.axvline(x=csps_total, color="red", linestyle="--", linewidth=1.5,
               label=f"CSPS = {csps_total:.1f}")

    ax.set_xlabel("Security Score (0-100)", fontsize=12)
    ax.set_title("Cloud Security Posture Score (CSPS) — Layer Breakdown", fontsize=13)
    ax.set_xlim(0, 110)
    ax.legend()
    ax.grid(axis="x", alpha=0.3)
    plt.tight_layout()

    path = os.path.join(output_dir, "fig2_csps_breakdown.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Figura 2 salvata: {path}")


def plot_remediation_rate(findings: list, output_dir: str):
    """Grafic 3 — Rata de remediere automata per layer."""
    if not HAS_MATPLOTLIB:
        return

    layers = list(LAYER_LABELS.keys())
    remediated = []
    not_remediated = []

    for layer in layers:
        lf = [f for f in findings if f["layer"] == layer]
        r = sum(1 for f in lf if f["auto_remediated"])
        remediated.append(r)
        not_remediated.append(len(lf) - r)

    fig, ax = plt.subplots(figsize=(10, 5))
    x = range(len(layers))
    width = 0.35

    ax.bar(x, remediated, width, label="Auto-remediated", color="#3B6D11", alpha=0.85)
    ax.bar([xi + width for xi in x], not_remediated, width,
           label="Manual action needed", color="#A32D2D", alpha=0.85)

    ax.set_xlabel("Security Layer", fontsize=12)
    ax.set_ylabel("Number of Findings", fontsize=12)
    ax.set_title("Auto-Remediation Rate per Security Layer", fontsize=13)
    ax.set_xticks([xi + width / 2 for xi in x])
    ax.set_xticklabels([LAYER_LABELS[l] for l in layers], rotation=15, ha="right")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()

    path = os.path.join(output_dir, "fig3_remediation_rate.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Figura 3 salvata: {path}")


def plot_score_heatmap(findings: list, output_dir: str):
    """Grafic 4 — Heatmap score per layer x severitate."""
    if not HAS_MATPLOTLIB or not HAS_PANDAS:
        return

    layers = list(LAYER_LABELS.keys())
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    matrix = []
    for sev in severities:
        row = []
        for layer in layers:
            scores = [f["score"] for f in findings
                      if f["layer"] == layer and f["severity"] == sev]
            row.append(round(sum(scores) / len(scores), 1) if scores else None)
        matrix.append(row)

    df = pd.DataFrame(
        matrix,
        index=severities,
        columns=[LAYER_LABELS[l] for l in layers],
    )

    fig, ax = plt.subplots(figsize=(11, 4))
    im = ax.imshow(
        [[v if v is not None else float("nan") for v in row] for row in matrix],
        cmap="RdYlGn", vmin=0, vmax=100, aspect="auto",
    )

    ax.set_xticks(range(len(layers)))
    ax.set_xticklabels([LAYER_LABELS[l] for l in layers], rotation=15, ha="right")
    ax.set_yticks(range(len(severities)))
    ax.set_yticklabels(severities)

    for i in range(len(severities)):
        for j in range(len(layers)):
            val = matrix[i][j]
            if val is not None:
                ax.text(j, i, f"{val:.0f}", ha="center", va="center",
                        fontsize=11, color="black")

    plt.colorbar(im, ax=ax, label="Avg Score (0-100)")
    ax.set_title("Average Security Score — Layer × Severity Heatmap", fontsize=13)
    plt.tight_layout()

    path = os.path.join(output_dir, "fig4_score_heatmap.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Figura 4 salvata: {path}")


def print_report(findings: list, stats: dict, csps: dict):
    """Afiseaza raportul in terminal."""
    print("\n" + "=" * 60)
    print("  SECUREPATH — ACADEMIC ANALYSIS REPORT")
    print("=" * 60)
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"  Total findings: {stats.get('total_findings', 0)}")
    print()

    print("  CSPS (Cloud Security Posture Score)")
    print(f"  {'Overall CSPS:':<30} {csps['csps']:.1f}/100")
    print()
    for layer, score in csps["breakdown"].items():
        label = LAYER_LABELS.get(layer, layer)
        bar = "█" * int(score / 5) + "░" * (20 - int(score / 5))
        print(f"  {label:<25} {bar} {score:.1f}")

    print()
    print("  FINDINGS BY SEVERITY")
    for sev in SEVERITY_ORDER:
        count = stats.get("by_severity", {}).get(sev, 0)
        if count > 0:
            print(f"  {sev:<12} {count:>4} findings")

    print()
    print("  AUTO-REMEDIATION")
    print(f"  Rate: {stats.get('auto_remediation_rate_pct', 0):.1f}%")

    print()
    print("  SCORE STATISTICS")
    print(f"  Mean:   {stats.get('score_mean', 0):.1f}")
    print(f"  Min:    {stats.get('score_min', 0):.1f}")
    print(f"  Max:    {stats.get('score_max', 0):.1f}")
    if "score_std" in stats:
        print(f"  StdDev: {stats.get('score_std', 0):.1f}")

    print()
    print("  FINDINGS BY LAYER")
    for layer, count in stats.get("by_layer", {}).items():
        label = LAYER_LABELS.get(layer, layer)
        print(f"  {label:<25} {count:>4} findings")

    print("=" * 60)


# ---------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SecurePath — Academic Data Analysis"
    )
    parser.add_argument("--region", default="eu-west-1",
                        help="AWS region (default: eu-west-1)")
    parser.add_argument("--output-dir", default="analysis_output",
                        help="Director pentru fisiere de output")
    parser.add_argument("--inject-demo", action="store_true",
                        help="Foloseste date demo daca DynamoDB e gol")
    parser.add_argument("--demo-only", action="store_true",
                        help="Foloseste DOAR date demo, nu contacta AWS")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print(f"\n[SecurePath Analysis] Region: {args.region}")
    print(f"[SecurePath Analysis] Output: {args.output_dir}/")

    # Fetch findings
    if args.demo_only:
        print("[INFO] Mod demo — folosesc date sintetice")
        raw_items = DEMO_FINDINGS
        findings = [normalize_item(i) for i in raw_items]
    elif HAS_BOTO3:
        print(f"[INFO] Extrag findings din DynamoDB ({TABLE_NAME})...")
        raw_items = fetch_findings(args.region)
        findings = [normalize_item(i) for i in raw_items]
        print(f"[INFO] Gasit {len(findings)} findings reale")

        if len(findings) == 0 and args.inject_demo:
            print("[INFO] Tabel gol — injectez date demo pentru vizualizare")
            raw_items = DEMO_FINDINGS
            findings = [normalize_item(i) for i in raw_items]
    else:
        print("[WARN] boto3 indisponibil — folosesc date demo")
        raw_items = DEMO_FINDINGS
        findings = [normalize_item(i) for i in raw_items]

    if not findings:
        print("[WARN] Nu exista findings. Ruleaza cu --inject-demo pentru date demo.")
        return

    # Calcule
    stats = compute_statistics(findings)
    csps = compute_csps(findings)

    # Output
    print_report(findings, stats, csps)
    export_csv(findings, args.output_dir)
    export_summary_json(stats, csps, args.output_dir)

    if HAS_MATPLOTLIB:
        print("\n[INFO] Generez grafice...")
        plot_severity_distribution(findings, args.output_dir)
        plot_csps_radar(csps, args.output_dir)
        plot_remediation_rate(findings, args.output_dir)
        if HAS_PANDAS:
            plot_score_heatmap(findings, args.output_dir)
        print(f"[OK] Toate graficele salvate in {args.output_dir}/")
    else:
        print("[WARN] matplotlib indisponibil — graficele nu au fost generate")

    print("\n[DONE] Analiza completa.")
    print(f"       Fisiere in: {os.path.abspath(args.output_dir)}/")


if __name__ == "__main__":
    main()
