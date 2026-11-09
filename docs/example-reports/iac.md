# SecWatch Security Report

Generated 2026-11-05 21:38 UTC · 9 findings

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 5 |
| Medium | 4 |
| Low | 0 |
| Info | 0 |

## Findings

| Severity | ID | Title | Entity | Count | ATT&CK |
|---|---|---|---|---|---|
| HIGH | IAC-IAM-01 | IAM policy grants full administrative access | `aws_iam_policy.too_broad` | 1 | T1078.004 Cloud Accounts |
| HIGH | IAC-RDS-01 | RDS storage is not encrypted | `aws_db_instance.app` | 1 |  |
| HIGH | IAC-RDS-02 | RDS instance is publicly accessible | `aws_db_instance.app` | 1 |  |
| HIGH | IAC-S3-01 | S3 bucket ACL grants public access | `aws_s3_bucket_acl.reports` | 1 | T1530 Data from Cloud Storage |
| HIGH | IAC-SG-01 | SSH open to the internet | `aws_security_group.web` | 1 | T1133 External Remote Services |
| MEDIUM | IAC-CT-02 | CloudTrail log file validation disabled | `aws_cloudtrail.main` | 1 |  |
| MEDIUM | IAC-CT-03 | CloudTrail is not multi-region | `aws_cloudtrail.main` | 1 |  |
| MEDIUM | IAC-EBS-01 | EBS volume is not encrypted | `aws_ebs_volume.data` | 1 |  |
| MEDIUM | IAC-S3-02 | S3 public access block is not fully enabled | `aws_s3_bucket_public_access_block.reports` | 1 |  |

## Details

### [HIGH] IAC-IAM-01: IAM policy grants full administrative access

A statement allows Action '*' on Resource '*'.

- **Entity:** `aws_iam_policy.too_broad`
- **MITRE ATT&CK:**  / T1078.004 Cloud Accounts
- **Remediation:** Scope actions and resources to least privilege.

### [HIGH] IAC-RDS-01: RDS storage is not encrypted

storage_encrypted is false or unset.

- **Entity:** `aws_db_instance.app`
- **Remediation:** Set storage_encrypted = true (requires a new instance for existing databases).

### [HIGH] IAC-RDS-02: RDS instance is publicly accessible

publicly_accessible is true.

- **Entity:** `aws_db_instance.app`
- **Remediation:** Set publicly_accessible = false and place the database in private subnets.

### [HIGH] IAC-S3-01: S3 bucket ACL grants public access

ACL is 'public-read'.

- **Entity:** `aws_s3_bucket_acl.reports`
- **MITRE ATT&CK:**  / T1530 Data from Cloud Storage
- **Remediation:** Use 'private' and serve content through CloudFront with OAC.

### [HIGH] IAC-SG-01: SSH open to the internet

Ingress 22-22 allows ['0.0.0.0/0'].

- **Entity:** `aws_security_group.web`
- **MITRE ATT&CK:**  / T1133 External Remote Services
- **Remediation:** Restrict to a known CIDR or use SSM Session Manager / a bastion.

### [MEDIUM] IAC-CT-02: CloudTrail log file validation disabled

Without validation, log tampering cannot be detected.

- **Entity:** `aws_cloudtrail.main`
- **Remediation:** Set enable_log_file_validation = true.

### [MEDIUM] IAC-CT-03: CloudTrail is not multi-region

Activity in other regions will not be logged.

- **Entity:** `aws_cloudtrail.main`
- **Remediation:** Set is_multi_region_trail = true.

### [MEDIUM] IAC-EBS-01: EBS volume is not encrypted

encrypted is false or unset.

- **Entity:** `aws_ebs_volume.data`
- **Remediation:** Set encrypted = true, or enable EBS encryption by default for the account.

### [MEDIUM] IAC-S3-02: S3 public access block is not fully enabled

Disabled settings: block_public_acls, block_public_policy.

- **Entity:** `aws_s3_bucket_public_access_block.reports`
- **Remediation:** Set all four public access block settings to true.
