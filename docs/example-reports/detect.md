# SecWatch Security Report

Generated 2026-11-05 21:38 UTC · 21 findings

| Severity | Count |
|---|---|
| Critical | 3 |
| High | 10 |
| Medium | 7 |
| Low | 1 |
| Info | 0 |

## Findings

| Severity | ID | Title | Entity | Count | ATT&CK |
|---|---|---|---|---|---|
| CRITICAL | AUTH-004 | Successful SSH login after repeated failures | `src_ip=203.0.113.45` | 41 | T1110 Brute Force |
| CRITICAL | AUTH-006 | Local account created with UID 0 | `user=sysupdate` | 1 | T1136.001 Create Account - Local Account |
| CRITICAL | AWS-003 | CloudTrail logging stopped or deleted | `user=svc-reporting, event_name=StopLogging` | 1 | T1562.008 Disable or Modify Cloud Logs |
| HIGH | AUTH-001 | SSH brute force against a single account source | `src_ip=203.0.113.45` | 40 | T1110.001 Password Guessing |
| HIGH | AUTH-002 | SSH password spraying across many usernames | `src_ip=203.0.113.77` | 9 | T1110.003 Password Spraying |
| HIGH | AUTH-003 | Successful SSH login as root | `src_ip=198.51.100.12, user=root` | 1 | T1078 Valid Accounts |
| HIGH | AUTH-005 | Sensitive file accessed via sudo | `user=deploy` | 2 | T1003.008 /etc/passwd and /etc/shadow |
| HIGH | AWS-001 | AWS root account activity | `event_name=ConsoleLogin, src_ip=198.51.100.11` | 1 | T1078.004 Cloud Accounts |
| HIGH | AWS-002 | Console login without MFA | `user=svc-reporting, src_ip=203.0.113.99` | 1 | T1078.004 Cloud Accounts |
| HIGH | AWS-004 | Security group opened to the internet | `user=svc-reporting` | 1 | T1562.007 Disable or Modify Cloud Firewall |
| HIGH | AWS-005 | Administrator policy attached to an identity | `user=svc-reporting` | 1 | T1098 Account Manipulation |
| HIGH | WEB-001 | SQL injection attempt in request | `src_ip=192.0.2.150` | 5 | T1190 Exploit Public-Facing Application |
| HIGH | WEB-002 | Path traversal attempt | `src_ip=192.0.2.150` | 2 | T1190 Exploit Public-Facing Application |
| MEDIUM | AWS-006 | New IAM access key created | `user=svc-reporting` | 1 | T1098.001 Additional Cloud Credentials |
| MEDIUM | AWS-007 | Burst of AccessDenied errors (cloud reconnaissance) | `user_arn=arn:aws:iam::111122223333:user/svc-reporting` | 10 | T1580 Cloud Infrastructure Discovery |
| MEDIUM | AWS-008 | Repeated failed console logins | `src_ip=203.0.113.99` | 6 | T1110 Brute Force |
| MEDIUM | WEB-003 | Known vulnerability scanner user agent | `src_ip=192.0.2.150` | 5 | T1595.002 Vulnerability Scanning |
| MEDIUM | WEB-003 | Known vulnerability scanner user agent | `src_ip=192.0.2.200` | 28 | T1595.002 Vulnerability Scanning |
| MEDIUM | WEB-004 | Directory brute forcing (burst of 404 responses) | `src_ip=192.0.2.200` | 24 | T1595.003 Wordlist Scanning |
| MEDIUM | WEB-005 | Access to sensitive files or admin paths | `src_ip=192.0.2.200` | 4 | T1595.003 Wordlist Scanning |
| LOW | AUTH-007 | New local account created | `user=dave` | 1 | T1136.001 Create Account - Local Account |

## Details

### [CRITICAL] AUTH-004: Successful SSH login after repeated failures

Several failed logins were followed by a success from the same IP, suggesting a brute force attack worked. 40 preceding events; success for user 'deploy'.

- **Entity:** `src_ip=203.0.113.45`
- **Seen:** 2026-03-10T10:13:02 to 2026-03-10T10:15:38 (41 events)
- **MITRE ATT&CK:** Credential Access / T1110 Brute Force
- **Remediation:** Treat the account as compromised, reset credentials, end active sessions, and review what the session did.

```
Mar 10 10:15:26 web01 sshd[15682]: Failed password for deploy from 203.0.113.45 port 60142 ssh2
Mar 10 10:15:32 web01 sshd[7985]: Failed password for deploy from 203.0.113.45 port 56748 ssh2
Mar 10 10:15:34 web01 sshd[20171]: Failed password for deploy from 203.0.113.45 port 55053 ssh2
Mar 10 10:15:38 web01 sshd[23070]: Accepted password for deploy from 203.0.113.45 port 51022 ssh2
```

### [CRITICAL] AUTH-006: Local account created with UID 0

A new account was created with root's UID, a common persistence technique.

- **Entity:** `user=sysupdate`
- **Seen:** 2026-03-10T10:18:38 to 2026-03-10T10:18:38 (1 events)
- **MITRE ATT&CK:** Persistence / T1136.001 Create Account - Local Account
- **Remediation:** Remove the account, audit /etc/passwd for other UID 0 entries, and investigate how it was created.

```
Mar 10 10:18:38 web01 useradd[26290]: new user: name=sysupdate, UID=0, GID=0, home=/root, shell=/bin/bash
```

### [CRITICAL] AWS-003: CloudTrail logging stopped or deleted

Someone disabled or deleted audit logging, a common step to hide malicious activity.

- **Entity:** `user=svc-reporting, event_name=StopLogging`
- **Seen:** 2026-03-10T14:18:00 to 2026-03-10T14:18:00 (1 events)
- **MITRE ATT&CK:** Defense Evasion / T1562.008 Disable or Modify Cloud Logs
- **Remediation:** Re-enable the trail, protect it with an SCP that denies StopLogging/DeleteTrail, and investigate the actor.

```
{"eventVersion": "1.09", "userIdentity": {"type": "IAMUser", "userName": "svc-reporting", "arn": "arn:aws:iam::111122223333:user/svc-reporting", "accountId": "111122223333"}, "eventTime": "2026-03-10T14:18:00Z", "eventSource": "cloudtrail.amazonaws.com", "eventName": "StopLogging", "awsRegion": "us-
```

### [HIGH] AUTH-001: SSH brute force against a single account source

Many failed SSH logins from one IP in a short window, typical of password guessing.

- **Entity:** `src_ip=203.0.113.45`
- **Seen:** 2026-03-10T10:13:02 to 2026-03-10T10:15:34 (40 events)
- **MITRE ATT&CK:** Credential Access / T1110.001 Password Guessing
- **Remediation:** Block the source IP, enforce key-based SSH authentication, and deploy fail2ban or equivalent rate limiting.

```
Mar 10 10:13:02 web01 sshd[3216]: Failed password for deploy from 203.0.113.45 port 42417 ssh2
Mar 10 10:13:05 web01 sshd[9946]: Failed password for deploy from 203.0.113.45 port 51826 ssh2
Mar 10 10:13:11 web01 sshd[1907]: Failed password for deploy from 203.0.113.45 port 52407 ssh2
Mar 10 10:13:13 web01 sshd[9013]: Failed password for deploy from 203.0.113.45 port 62252 ssh2
Mar 10 10:13:15 web01 sshd[19029]: Failed password for deploy from 203.0.113.45 port 57690 ssh2
```

### [HIGH] AUTH-002: SSH password spraying across many usernames

One IP tried many different usernames, which suggests password spraying or username enumeration. Distinct user values: 9.

- **Entity:** `src_ip=203.0.113.77`
- **Seen:** 2026-03-10T13:00:21 to 2026-03-10T13:03:21 (9 events)
- **MITRE ATT&CK:** Credential Access / T1110.003 Password Spraying
- **Remediation:** Block the source, review whether any targeted account later logged in successfully, and disable password authentication.

```
Mar 10 13:00:21 web01 sshd[5741]: Failed password for invalid user admin from 203.0.113.77 port 41058 ssh2
Mar 10 13:00:35 web01 sshd[8473]: Failed password for invalid user test from 203.0.113.77 port 43529 ssh2
Mar 10 13:01:04 web01 sshd[6367]: Failed password for invalid user oracle from 203.0.113.77 port 53393 ssh2
Mar 10 13:01:18 web01 sshd[22713]: Failed password for invalid user postgres from 203.0.113.77 port 46597 ssh2
Mar 10 13:01:36 web01 sshd[16869]: Failed password for invalid user ubuntu from 203.0.113.77 port 52662 ssh2
```

### [HIGH] AUTH-003: Successful SSH login as root

Direct root login over SSH bypasses individual accountability and should be disabled.

- **Entity:** `src_ip=198.51.100.12, user=root`
- **Seen:** 2026-03-10T15:42:00 to 2026-03-10T15:42:00 (1 events)
- **MITRE ATT&CK:** Initial Access / T1078 Valid Accounts
- **Remediation:** Set PermitRootLogin no in sshd_config and require named accounts with sudo.

```
Mar 10 15:42:00 web01 sshd[10207]: Accepted publickey for root from 198.51.100.12 port 60111 ssh2
```

### [HIGH] AUTH-005: Sensitive file accessed via sudo

A user ran a sudo command touching credential stores such as /etc/shadow.

- **Entity:** `user=deploy`
- **Seen:** 2026-03-10T10:17:38 to 2026-03-10T10:19:38 (2 events)
- **MITRE ATT&CK:** Credential Access / T1003.008 /etc/passwd and /etc/shadow
- **Remediation:** Confirm the activity was authorized and restrict sudo rules to the minimum commands needed.

```
Mar 10 10:17:38 web01 sudo[29082]:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
Mar 10 10:19:38 web01 sudo[12900]:   deploy : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/vi /root/.ssh/authorized_keys
```

### [HIGH] AWS-001: AWS root account activity

The root user performed an API or console action. Root should be locked away and used only for break-glass tasks.

- **Entity:** `event_name=ConsoleLogin, src_ip=198.51.100.11`
- **Seen:** 2026-03-10T09:30:00 to 2026-03-10T09:30:00 (1 events)
- **MITRE ATT&CK:** Privilege Escalation / T1078.004 Cloud Accounts
- **Remediation:** Confirm the activity was approved, ensure root has hardware MFA, and use IAM roles for daily work.

```
{"eventVersion": "1.09", "userIdentity": {"type": "Root", "arn": "arn:aws:iam::111122223333:root", "accountId": "111122223333"}, "eventTime": "2026-03-10T09:30:00Z", "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin", "awsRegion": "us-east-1", "sourceIPAddress": "198.51.100.11", "use
```

### [HIGH] AWS-002: Console login without MFA

A successful AWS console login did not use multi-factor authentication.

- **Entity:** `user=svc-reporting, src_ip=203.0.113.99`
- **Seen:** 2026-03-10T14:13:00 to 2026-03-10T14:13:00 (1 events)
- **MITRE ATT&CK:** Initial Access / T1078.004 Cloud Accounts
- **Remediation:** Enforce MFA with an IAM policy condition (aws:MultiFactorAuthPresent) and require MFA enrollment.

```
{"eventVersion": "1.09", "userIdentity": {"type": "IAMUser", "userName": "svc-reporting", "arn": "arn:aws:iam::111122223333:user/svc-reporting", "accountId": "111122223333"}, "eventTime": "2026-03-10T14:13:00Z", "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin", "awsRegion": "us-eas
```

### [HIGH] AWS-004: Security group opened to the internet

An ingress rule allowing 0.0.0.0/0 or ::/0 was added to a security group.

- **Entity:** `user=svc-reporting`
- **Seen:** 2026-03-10T14:17:00 to 2026-03-10T14:17:00 (1 events)
- **MITRE ATT&CK:** Defense Evasion / T1562.007 Disable or Modify Cloud Firewall
- **Remediation:** Restrict the rule to known CIDRs or use SSM Session Manager instead of public SSH/RDP.

```
{"eventVersion": "1.09", "userIdentity": {"type": "IAMUser", "userName": "svc-reporting", "arn": "arn:aws:iam::111122223333:user/svc-reporting", "accountId": "111122223333"}, "eventTime": "2026-03-10T14:17:00Z", "eventSource": "ec2.amazonaws.com", "eventName": "AuthorizeSecurityGroupIngress", "awsRe
```

### [HIGH] AWS-005: Administrator policy attached to an identity

AdministratorAccess (or another full-access policy) was attached to a user, group, or role.

- **Entity:** `user=svc-reporting`
- **Seen:** 2026-03-10T14:16:00 to 2026-03-10T14:16:00 (1 events)
- **MITRE ATT&CK:** Persistence / T1098 Account Manipulation
- **Remediation:** Verify against change management, and prefer least-privilege, role-based access.

```
{"eventVersion": "1.09", "userIdentity": {"type": "IAMUser", "userName": "svc-reporting", "arn": "arn:aws:iam::111122223333:user/svc-reporting", "accountId": "111122223333"}, "eventTime": "2026-03-10T14:16:00Z", "eventSource": "iam.amazonaws.com", "eventName": "AttachUserPolicy", "awsRegion": "us-ea
```

### [HIGH] WEB-001: SQL injection attempt in request

The request path contains common SQL injection payload patterns.

- **Entity:** `src_ip=192.0.2.150`
- **Seen:** 2026-03-10T12:30:07 to 2026-03-10T12:30:35 (5 events)
- **MITRE ATT&CK:** Initial Access / T1190 Exploit Public-Facing Application
- **Remediation:** Confirm queries are parameterized, review the WAF rules, and check whether any of these requests returned 200 with unusual sizes.

```
192.0.2.150 - - [10/Mar/2026:12:30:07 +0000] "GET /products?id=42%27%20OR%20%271%27=%271 HTTP/1.1" 500 1527 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
192.0.2.150 - - [10/Mar/2026:12:30:14 +0000] "GET /products?id=42%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 200 2033 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
192.0.2.150 - - [10/Mar/2026:12:30:21 +0000] "GET /products?id=42;%20DROP%20TABLE%20users-- HTTP/1.1" 500 5931 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
192.0.2.150 - - [10/Mar/2026:12:30:28 +0000] "GET /products?id=42%20AND%20SLEEP(5) HTTP/1.1" 500 6101 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
192.0.2.150 - - [10/Mar/2026:12:30:35 +0000] "GET /api/items?sort=(SELECT%20table_name%20FROM%20information_schema.tables) HTTP/1.1" 200 4529 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
```

### [HIGH] WEB-002: Path traversal attempt

The request attempts to escape the web root to read local files.

- **Entity:** `src_ip=192.0.2.150`
- **Seen:** 2026-03-10T12:30:40 to 2026-03-10T12:30:45 (2 events)
- **MITRE ATT&CK:** Initial Access / T1190 Exploit Public-Facing Application
- **Remediation:** Validate and canonicalize file paths server-side, and block the source IP.

```
192.0.2.150 - - [10/Mar/2026:12:30:40 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 400 8733 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
192.0.2.150 - - [10/Mar/2026:12:30:45 +0000] "GET /download?file=..%2F..%2F..%2Fetc%2Fshadow HTTP/1.1" 400 3203 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
```

### [MEDIUM] AWS-006: New IAM access key created

A long-lived access key was created, which attackers use to keep access to a cloud account.

- **Entity:** `user=svc-reporting`
- **Seen:** 2026-03-10T14:15:00 to 2026-03-10T14:15:00 (1 events)
- **MITRE ATT&CK:** Persistence / T1098.001 Additional Cloud Credentials
- **Remediation:** Confirm the key is expected; prefer short-lived role credentials over IAM user keys.

```
{"eventVersion": "1.09", "userIdentity": {"type": "IAMUser", "userName": "svc-reporting", "arn": "arn:aws:iam::111122223333:user/svc-reporting", "accountId": "111122223333"}, "eventTime": "2026-03-10T14:15:00Z", "eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey", "awsRegion": "us-eas
```

### [MEDIUM] AWS-007: Burst of AccessDenied errors (cloud reconnaissance)

Many denied API calls from one identity, which often means stolen credentials are being used to explore permissions.

- **Entity:** `user_arn=arn:aws:iam::111122223333:user/svc-reporting`
- **Seen:** 2026-03-10T14:08:12 to 2026-03-10T14:10:00 (10 events)
- **MITRE ATT&CK:** Discovery / T1580 Cloud Infrastructure Discovery
- **Remediation:** Investigate where the credentials are being used, and rotate them if the activity is not recognized.

```
{"eventVersion": "1.09", "userIdentity": {"type": "IAMUser", "userName": "svc-reporting", "arn": "arn:aws:iam::111122223333:user/svc-reporting", "accountId": "111122223333"}, "eventTime": "2026-03-10T14:08:12Z", "eventSource": "iam.amazonaws.com", "eventName": "ListUsers", "awsRegion": "us-east-1", 
{"eventVersion": "1.09", "userIdentity": {"type": "IAMUser", "userName": "svc-reporting", "arn": "arn:aws:iam::111122223333:user/svc-reporting", "accountId": "111122223333"}, "eventTime": "2026-03-10T14:08:24Z", "eventSource": "iam.amazonaws.com", "eventName": "ListRoles", "awsRegion": "us-east-1", 
{"eventVersion": "1.09", "userIdentity": {"type": "IAMUser", "userName": "svc-reporting", "arn": "arn:aws:iam::111122223333:user/svc-reporting", "accountId": "111122223333"}, "eventTime": "2026-03-10T14:08:36Z", "eventSource": "iam.amazonaws.com", "eventName": "GetAccountAuthorizationDetails", "awsR
{"eventVersion": "1.09", "userIdentity": {"type": "IAMUser", "userName": "svc-reporting", "arn": "arn:aws:iam::111122223333:user/svc-reporting", "accountId": "111122223333"}, "eventTime": "2026-03-10T14:08:48Z", "eventSource": "ec2.amazonaws.com", "eventName": "DescribeInstances", "awsRegion": "us-e
{"eventVersion": "1.09", "userIdentity": {"type": "IAMUser", "userName": "svc-reporting", "arn": "arn:aws:iam::111122223333:user/svc-reporting", "accountId": "111122223333"}, "eventTime": "2026-03-10T14:09:00Z", "eventSource": "secretsmanager.amazonaws.com", "eventName": "ListSecrets", "awsRegion": 
```

### [MEDIUM] AWS-008: Repeated failed console logins

Several failed AWS console logins in a short window.

- **Entity:** `src_ip=203.0.113.99`
- **Seen:** 2026-03-10T14:00:30 to 2026-03-10T14:03:00 (6 events)
- **MITRE ATT&CK:** Credential Access / T1110 Brute Force
- **Remediation:** Confirm MFA is enforced and review the targeted accounts.

```
{"eventVersion": "1.09", "userIdentity": {"type": "IAMUser", "userName": "bob", "arn": "arn:aws:iam::111122223333:user/bob", "accountId": "111122223333"}, "eventTime": "2026-03-10T14:00:30Z", "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin", "awsRegion": "us-east-1", "sourceIPAddre
{"eventVersion": "1.09", "userIdentity": {"type": "IAMUser", "userName": "bob", "arn": "arn:aws:iam::111122223333:user/bob", "accountId": "111122223333"}, "eventTime": "2026-03-10T14:01:00Z", "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin", "awsRegion": "us-east-1", "sourceIPAddre
{"eventVersion": "1.09", "userIdentity": {"type": "IAMUser", "userName": "bob", "arn": "arn:aws:iam::111122223333:user/bob", "accountId": "111122223333"}, "eventTime": "2026-03-10T14:01:30Z", "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin", "awsRegion": "us-east-1", "sourceIPAddre
{"eventVersion": "1.09", "userIdentity": {"type": "IAMUser", "userName": "bob", "arn": "arn:aws:iam::111122223333:user/bob", "accountId": "111122223333"}, "eventTime": "2026-03-10T14:02:00Z", "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin", "awsRegion": "us-east-1", "sourceIPAddre
{"eventVersion": "1.09", "userIdentity": {"type": "IAMUser", "userName": "bob", "arn": "arn:aws:iam::111122223333:user/bob", "accountId": "111122223333"}, "eventTime": "2026-03-10T14:02:30Z", "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin", "awsRegion": "us-east-1", "sourceIPAddre
```

### [MEDIUM] WEB-003: Known vulnerability scanner user agent

The user agent matches a well-known automated scanning tool.

- **Entity:** `src_ip=192.0.2.150`
- **Seen:** 2026-03-10T12:30:07 to 2026-03-10T12:30:35 (5 events)
- **MITRE ATT&CK:** Reconnaissance / T1595.002 Vulnerability Scanning
- **Remediation:** Rate-limit or block the source, and confirm scanning is not from an authorized internal assessment.

```
192.0.2.150 - - [10/Mar/2026:12:30:07 +0000] "GET /products?id=42%27%20OR%20%271%27=%271 HTTP/1.1" 500 1527 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
192.0.2.150 - - [10/Mar/2026:12:30:14 +0000] "GET /products?id=42%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 200 2033 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
192.0.2.150 - - [10/Mar/2026:12:30:21 +0000] "GET /products?id=42;%20DROP%20TABLE%20users-- HTTP/1.1" 500 5931 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
192.0.2.150 - - [10/Mar/2026:12:30:28 +0000] "GET /products?id=42%20AND%20SLEEP(5) HTTP/1.1" 500 6101 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
192.0.2.150 - - [10/Mar/2026:12:30:35 +0000] "GET /api/items?sort=(SELECT%20table_name%20FROM%20information_schema.tables) HTTP/1.1" 200 4529 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
```

### [MEDIUM] WEB-003: Known vulnerability scanner user agent

The user agent matches a well-known automated scanning tool.

- **Entity:** `src_ip=192.0.2.200`
- **Seen:** 2026-03-10T11:00:02 to 2026-03-10T11:00:56 (28 events)
- **MITRE ATT&CK:** Reconnaissance / T1595.002 Vulnerability Scanning
- **Remediation:** Rate-limit or block the source, and confirm scanning is not from an authorized internal assessment.

```
192.0.2.200 - - [10/Mar/2026:11:00:02 +0000] "GET /admin HTTP/1.1" 404 196 "-" "Nikto/2.5.0"
192.0.2.200 - - [10/Mar/2026:11:00:04 +0000] "GET /backup HTTP/1.1" 404 196 "-" "Nikto/2.5.0"
192.0.2.200 - - [10/Mar/2026:11:00:06 +0000] "GET /old HTTP/1.1" 404 196 "-" "Nikto/2.5.0"
192.0.2.200 - - [10/Mar/2026:11:00:08 +0000] "GET /test HTTP/1.1" 404 196 "-" "Nikto/2.5.0"
192.0.2.200 - - [10/Mar/2026:11:00:10 +0000] "GET /dev HTTP/1.1" 404 196 "-" "Nikto/2.5.0"
```

### [MEDIUM] WEB-004: Directory brute forcing (burst of 404 responses)

One IP generated many 404 responses quickly, consistent with wordlist-based content discovery.

- **Entity:** `src_ip=192.0.2.200`
- **Seen:** 2026-03-10T11:00:02 to 2026-03-10T11:00:48 (24 events)
- **MITRE ATT&CK:** Reconnaissance / T1595.003 Wordlist Scanning
- **Remediation:** Rate-limit the source and make sure no sensitive paths (backups, .git, admin panels) are exposed.

```
192.0.2.200 - - [10/Mar/2026:11:00:02 +0000] "GET /admin HTTP/1.1" 404 196 "-" "Nikto/2.5.0"
192.0.2.200 - - [10/Mar/2026:11:00:04 +0000] "GET /backup HTTP/1.1" 404 196 "-" "Nikto/2.5.0"
192.0.2.200 - - [10/Mar/2026:11:00:06 +0000] "GET /old HTTP/1.1" 404 196 "-" "Nikto/2.5.0"
192.0.2.200 - - [10/Mar/2026:11:00:08 +0000] "GET /test HTTP/1.1" 404 196 "-" "Nikto/2.5.0"
192.0.2.200 - - [10/Mar/2026:11:00:10 +0000] "GET /dev HTTP/1.1" 404 196 "-" "Nikto/2.5.0"
```

### [MEDIUM] WEB-005: Access to sensitive files or admin paths

A request targeted files that should never be publicly exposed, such as .env or .git.

- **Entity:** `src_ip=192.0.2.200`
- **Seen:** 2026-03-10T11:00:50 to 2026-03-10T11:00:56 (4 events)
- **MITRE ATT&CK:** Reconnaissance / T1595.003 Wordlist Scanning
- **Remediation:** Confirm these paths return 404, and rotate any secrets if a 200 response was served for .env or .git.

```
192.0.2.200 - - [10/Mar/2026:11:00:50 +0000] "GET /.env HTTP/1.1" 403 300 "-" "Nikto/2.5.0"
192.0.2.200 - - [10/Mar/2026:11:00:52 +0000] "GET /.git/config HTTP/1.1" 403 300 "-" "Nikto/2.5.0"
192.0.2.200 - - [10/Mar/2026:11:00:54 +0000] "GET /wp-admin/ HTTP/1.1" 301 300 "-" "Nikto/2.5.0"
192.0.2.200 - - [10/Mar/2026:11:00:56 +0000] "GET /server-status HTTP/1.1" 403 300 "-" "Nikto/2.5.0"
```

### [LOW] AUTH-007: New local account created

A new local account was created. Low severity by itself, but useful context during investigations.

- **Entity:** `user=dave`
- **Seen:** 2026-03-10T16:00:00 to 2026-03-10T16:00:00 (1 events)
- **MITRE ATT&CK:** Persistence / T1136.001 Create Account - Local Account
- **Remediation:** Verify the account matches an approved change request.

```
Mar 10 16:00:00 web01 useradd[16871]: new user: name=dave, UID=1005, GID=1005, home=/home/dave, shell=/bin/bash
```
