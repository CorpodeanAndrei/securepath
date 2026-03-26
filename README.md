# SecurePath

**Automated Cloud Security & Compliance System for AWS**

Five security layers running continuously, all verified by Terraform IaC state.

## Architecture

| Layer | Module | Detects | Auto-remediates |
|-------|--------|---------|-----------------|
| 1 | Supply Chain | Malicious Docker images, CVE-CRITICAL/HIGH | Blocks ECR push |
| 2 | Zero-Trust IAM | Unauthorized IAM mutations, blast radius | Alerts + PR |
| 3 | Drift Detector | Manual infra changes vs tfstate | Auto or PR |
| 4 | Policy Engine | S3 public, open SGs, missing tags | Re-enables controls |
| 5 | Chaos Prober | Resilience SLA breach (RTO, MTTR, GDS) | Alert + report |

## Quick Start

### Prerequisites

- AWS CLI configured (`aws configure`)
- Terraform >= 1.9
- Docker (for supply chain tests)
- Git

### 1. AWS Setup

```bash
cd scripts
chmod +x setup-aws.sh
./setup-aws.sh your-github-username/securepath
```

### 2. Configure Terraform

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your account_id and github_repo
```

### 3. Deploy

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

### 4. Subscribe to alerts

```bash
aws sns subscribe \
  --topic-arn $(terraform output -raw alerts_topic_arn) \
  --protocol email \
  --notification-endpoint your@email.com
```

### 5. Run a local scan

```powershell
.\scripts\local-scan.ps1
```

## Testing Attack Scenarios

### Test 1 — Malicious Docker image

```bash
# Build an image with a known vulnerable base
echo "FROM python:3.8" > Dockerfile
docker build -t test-vuln .
# Push to ECR — supply chain scanner triggers automatically
```

### Test 2 — IAM mutation

```bash
# Attach AdministratorAccess to a role (triggers IAM analyzer)
aws iam attach-role-policy \
  --role-name test-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
# Check DynamoDB findings table for alert
```

### Test 3 — Infrastructure drift

```bash
# Disable S3 encryption directly in console or via CLI
aws s3api delete-bucket-encryption --bucket securepath-config-dev
# Wait 30 minutes (or trigger Lambda manually) — drift detected
```

### Test 4 — Policy violation

```bash
# Open SSH to the world on a security group
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxx \
  --protocol tcp --port 22 --cidr 0.0.0.0/0
# Policy enforcer Lambda triggers and revokes within seconds
```

## Project Structure

```
securepath/
├── .github/workflows/    # CI/CD pipelines
├── terraform/            # All infrastructure as code
│   └── modules/          # One module per security layer
├── lambdas/              # Python handlers for each layer
├── policies/             # OPA Rego rules + AWS SCPs
├── scripts/              # Setup and local scan tools
└── findings_schema.json  # Unified findings format
```

## Academic Context

This system is designed as an empirical study platform for:

- **RQ1**: Which attack surface has the highest auto-remediation rate?
- **RQ2**: What is the mean detection latency per layer?
- **RQ3**: Does Terraform drift detection outperform manual Config rules?

All findings are stored in DynamoDB with a unified JSON schema enabling
cross-layer analysis and CSPS (Cloud Security Posture Score) calculation.
