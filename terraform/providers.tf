terraform {
  required_version = ">= 1.9.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }

  backend "s3" {
    # Replace ACCOUNT_ID after running scripts/setup-aws.sh
    bucket         = "securepath-tfstate-389708013299"
    key        = "securepath/terraform.tfstate"
    region     = "us-east-1"
    use_lockfile = true                               # fix pentru warning-ul deprecated
    encrypt    = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "SecurePath"
      ManagedBy   = "Terraform"
      Environment = var.environment
      Repository  = "https://github.com/CorpodeanAndrei"
    }
  }
}
