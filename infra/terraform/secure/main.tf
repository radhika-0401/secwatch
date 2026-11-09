# Hardened counterpart to ../main.tf. Every SecWatch IaC check passes.
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "admin_cidr" {
  description = "Corporate VPN CIDR allowed to reach SSH"
  type        = string
}

variable "db_password" {
  type      = string
  sensitive = true
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
    description = "SSH from the corporate VPN only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
}

resource "aws_s3_bucket" "reports" {
  bucket = "secwatch-demo-reports-111122223333"
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
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
  storage_encrypted   = true
  publicly_accessible = false
  skip_final_snapshot = true
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 50
  encrypted         = true
}

resource "aws_iam_policy" "developer" {
  name = "developer-read-only-ec2"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ec2:Describe*"]
      Resource = "*"
    }]
  })
}

resource "aws_cloudtrail" "main" {
  name                       = "org-trail"
  s3_bucket_name             = aws_s3_bucket.reports.id
  enable_logging             = true
  is_multi_region_trail      = true
  enable_log_file_validation = true
}
