# SecurePath OPA Policy — Terraform IaC checks
# Run: conftest test terraform/ --policy policies/opa

package main

import future.keywords

# -------------------------------------------------------
# DENY: S3 bucket without encryption
# -------------------------------------------------------
deny contains msg if {
    resource := input.resource.aws_s3_bucket[name]
    not resource.server_side_encryption_configuration
    msg := sprintf("S3 bucket '%s' must have server_side_encryption_configuration", [name])
}

# -------------------------------------------------------
# DENY: S3 bucket without public access block
# -------------------------------------------------------
deny contains msg if {
    resource := input.resource.aws_s3_bucket_public_access_block[name]
    not resource.block_public_acls == true
    msg := sprintf("S3 bucket '%s' must block public ACLs", [name])
}

deny contains msg if {
    resource := input.resource.aws_s3_bucket_public_access_block[name]
    not resource.restrict_public_buckets == true
    msg := sprintf("S3 bucket '%s' must restrict public buckets", [name])
}

# -------------------------------------------------------
# DENY: Security group open to 0.0.0.0/0 on sensitive ports
# -------------------------------------------------------
sensitive_ports := {22, 3389, 3306, 5432, 6379, 27017}

deny contains msg if {
    resource := input.resource.aws_security_group_rule[name]
    resource.type == "ingress"
    resource.cidr_blocks[_] == "0.0.0.0/0"
    resource.from_port <= port
    resource.to_port >= port
    port := sensitive_ports[_]
    msg := sprintf(
        "Security group rule '%s' opens port %d to 0.0.0.0/0",
        [name, port]
    )
}

# -------------------------------------------------------
# DENY: IAM role with administrator access
# -------------------------------------------------------
deny contains msg if {
    resource := input.resource.aws_iam_role_policy_attachment[name]
    resource.policy_arn == "arn:aws:iam::aws:policy/AdministratorAccess"
    msg := sprintf("IAM role attachment '%s' must not use AdministratorAccess", [name])
}

# -------------------------------------------------------
# DENY: Resources missing required tags
# -------------------------------------------------------
required_tags := {"Project", "Environment", "ManagedBy"}

deny contains msg if {
    resource := input.resource.aws_instance[name]
    missing := required_tags - {k | resource.tags[k]}
    count(missing) > 0
    msg := sprintf("EC2 instance '%s' missing required tags: %v", [name, missing])
}

deny contains msg if {
    resource := input.resource.aws_s3_bucket[name]
    missing := required_tags - {k | resource.tags[k]}
    count(missing) > 0
    msg := sprintf("S3 bucket '%s' missing required tags: %v", [name, missing])
}

# -------------------------------------------------------
# WARN: Lambda without reserved concurrency
# -------------------------------------------------------
warn contains msg if {
    resource := input.resource.aws_lambda_function[name]
    not resource.reserved_concurrent_executions
    msg := sprintf(
        "Lambda '%s' has no reserved concurrency — consider setting it to prevent noisy-neighbor issues",
        [name]
    )
}

# -------------------------------------------------------
# WARN: DynamoDB without point-in-time recovery
# -------------------------------------------------------
warn contains msg if {
    resource := input.resource.aws_dynamodb_table[name]
    not resource.point_in_time_recovery.enabled == true
    msg := sprintf("DynamoDB table '%s' should enable point_in_time_recovery", [name])
}
