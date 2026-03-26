#!/bin/bash
# =============================================================
# SecurePath — AWS Prerequisites Setup
# Run this ONCE before terraform init
# Requires: AWS CLI configured with admin permissions
# =============================================================
set -euo pipefail

REGION="eu-west-1"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
PROJECT="securepath"
GITHUB_REPO="${1:-CorpodeanAndrei/securepath}"

echo ""
echo "  Setting up SecurePath prerequisites"
echo "  Account: $ACCOUNT_ID | Region: $REGION"
echo ""

# 1. S3 bucket for Terraform state
BUCKET_NAME="${PROJECT}-tfstate-${ACCOUNT_ID}"
echo "[1/5] Creating Terraform state bucket: $BUCKET_NAME"
aws s3 mb "s3://${BUCKET_NAME}" --region "$REGION" 2>/dev/null || echo "  Bucket already exists"
aws s3api put-bucket-versioning \
  --bucket "$BUCKET_NAME" \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption \
  --bucket "$BUCKET_NAME" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
aws s3api put-public-access-block \
  --bucket "$BUCKET_NAME" \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# 2. DynamoDB table for state locking
echo "[2/5] Creating DynamoDB lock table"
aws dynamodb create-table \
  --table-name "${PROJECT}-tf-locks" \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region "$REGION" 2>/dev/null || echo "  Table already exists"

# 3. GitHub OIDC provider
echo "[3/5] Creating GitHub OIDC provider"
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1 2>/dev/null || echo "  OIDC provider already exists"

# 4. IAM role for GitHub Actions
echo "[4/5] Creating GitHub Actions IAM role"
TRUST_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::${ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      },
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:${GITHUB_REPO}:*"
      }
    }
  }]
}
EOF
)
aws iam create-role \
  --role-name "${PROJECT}-github-actions" \
  --assume-role-policy-document "$TRUST_POLICY" 2>/dev/null || echo "  Role already exists"

# Attach policies (scoped for this project only)
aws iam attach-role-policy \
  --role-name "${PROJECT}-github-actions" \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess 2>/dev/null || true

echo "[5/5] Update providers.tf with your account ID"
sed -i "s/REPLACE_ACCOUNT_ID/${ACCOUNT_ID}/g" ../terraform/providers.tf 2>/dev/null || true

echo ""
echo "  Prerequisites complete!"
echo "  Next steps:"
echo "  1. Add GitHub secrets: AWS_ACCOUNT_ID=${ACCOUNT_ID}"
echo "  2. cd terraform && terraform init"
echo "  3. terraform plan -var account_id=${ACCOUNT_ID} -var github_repo=${GITHUB_REPO}"
echo "  4. terraform apply"
echo ""
