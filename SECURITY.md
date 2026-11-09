# Security Policy

SecWatch is a defensive, read-only toolkit. It parses logs and configuration
files and never modifies the systems it audits.

All sample data uses RFC 5737 documentation IP ranges and fake AWS account IDs.
The Terraform in `infra/terraform/main.tf` is intentionally insecure and must
never be applied.

To report a vulnerability in SecWatch itself, please open a private security
advisory on this repository instead of a public issue.
