# Threat Model: Sample Web Application Environment

This document models the small environment that SecWatch's sample data represents and
explains which detections and controls address each threat. It uses the STRIDE method.

## System overview

```mermaid
flowchart LR
    U[Internet users] -->|HTTPS 443| W[web01: Nginx + app]
    A[Admins / CI] -->|SSH 22| W
    W -->|SQL| DB[(RDS PostgreSQL)]
    W -->|Reports| S3[(S3 bucket)]
    A -->|Console / API| AWS[AWS control plane]
    AWS -->|Audit events| CT[CloudTrail]
    W -.auth.log / access.log.-> SW[SecWatch]
    CT -.events.-> SW
```

**Assets:** customer data in RDS, report files in S3, AWS IAM credentials, the web01 host.

**Trust boundaries:** internet to web tier; admin network to SSH; application to database;
any identity to the AWS control plane.

## STRIDE analysis

| Threat | Example abuse case | Detection (SecWatch) | Preventive control |
|---|---|---|---|
| **S**poofing | Attacker guesses the `deploy` SSH password | AUTH-001, AUTH-002, AUTH-004 | Key-only SSH (HARD-SSH-02), fail2ban, MFA |
| **S**poofing | Leaked IAM credentials used from a new IP | AWS-002, AWS-007, AWS-008 | Enforce MFA, short-lived role credentials |
| **T**ampering | Attacker opens SSH to 0.0.0.0/0 | AWS-004 | IAC-SG-01 blocks it in CI before deploy |
| **T**ampering | SQL injection modifies data | WEB-001 | Parameterized queries, WAF |
| **R**epudiation | Attacker stops CloudTrail to hide actions | AWS-003 | SCP denying StopLogging, IAC-CT-01/02/03 |
| **R**epudiation | Shared root login hides who acted | AUTH-003, AWS-001 | PermitRootLogin no (HARD-SSH-01), named accounts |
| **I**nformation disclosure | Public S3 bucket leaks reports | IAC-S3-01, IAC-S3-02 | Public access block on all buckets |
| **I**nformation disclosure | Path traversal reads /etc/passwd | WEB-002 | Path canonicalization, least-privilege service user |
| **I**nformation disclosure | Exposed `.env` or `.git` | WEB-005 | Deny dotfiles at the web server |
| **D**enial of service | Wordlist scanning floods the app | WEB-003, WEB-004 | Rate limiting, CDN/WAF |
| **E**levation of privilege | Backdoor account with UID 0 | AUTH-006, HARD-ACCT-01 | File integrity monitoring on /etc/passwd |
| **E**levation of privilege | AdministratorAccess attached to a service user | AWS-005, AWS-006 | IAC-IAM-01, permission boundaries |
| **E**levation of privilege | sudo used to read /etc/shadow | AUTH-005 | Minimal sudoers rules, HARD-PERM-01 |

## Attack chains in the sample data

**Linux host compromise:** password brute force against `deploy` (AUTH-001) → successful
login (AUTH-004) → `sudo cat /etc/shadow` (AUTH-005) → UID 0 backdoor `sysupdate`
(AUTH-006) → SSH key persistence (AUTH-005). The hardening audit then independently finds
the leftover backdoor (HARD-ACCT-01, HARD-ACCT-02), showing how posture checks and log
detections support each other.

**AWS account compromise:** failed console logins (AWS-008) → permission probing with stolen
`svc-reporting` keys (AWS-007) → console login without MFA (AWS-002) → new access key
(AWS-006) → AdministratorAccess (AWS-005) → SSH opened to the world (AWS-004) → CloudTrail
stopped (AWS-003).

## Known gaps and future work

Detections run in batch on files rather than streaming. There is no IP reputation or
geolocation enrichment, so impossible-travel style detections are not implemented. The IaC
scanner covers a focused set of AWS resources rather than the full provider. These are
documented in the README roadmap.
