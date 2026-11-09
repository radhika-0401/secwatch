# ---------------------------------------------------------------------------
# INTENTIONALLY INSECURE: DO NOT DEPLOY.
# This configuration exists only so SecWatch's IaC scanner has realistic
# misconfigurations to find. See infra/terraform/secure/ for the fixed version.
# ---------------------------------------------------------------------------
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Web server security group"

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH from anywhere (bad)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "reports" {
  bucket = "secwatch-demo-reports-111122223333"
}

resource "aws_s3_bucket_acl" "reports" {
  bucket = aws_s3_bucket.reports.id
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_db_instance" "app" {
  identifier          = "app-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "appadmin"
  password            = var.db_password
  storage_encrypted   = false
  publicly_accessible = true
  skip_final_snapshot = true
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 50
  encrypted         = false
}

resource "aws_iam_policy" "too_broad" {
  name = "developer-everything"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_cloudtrail" "main" {
  name                       = "org-trail"
  s3_bucket_name             = aws_s3_bucket.reports.id
  enable_logging             = true
  is_multi_region_trail      = false
  enable_log_file_validation = false
}

variable "db_password" {
  type      = string
  sensitive = true
}
