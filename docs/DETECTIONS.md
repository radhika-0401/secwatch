# Detection Catalog

Every rule lives in `secwatch/rules/*.yml` and maps to a MITRE ATT&CK technique.
This table is generated from the rule files.

| ID | Type | Severity | Detection | MITRE ATT&CK tactic | Technique |
|---|---|---|---|---|---|
| AWS-001 | match | high | AWS root account activity | Privilege Escalation | T1078.004 Cloud Accounts |
| AWS-002 | match | high | Console login without MFA | Initial Access | T1078.004 Cloud Accounts |
| AWS-003 | match | critical | CloudTrail logging stopped or deleted | Defense Evasion | T1562.008 Disable or Modify Cloud Logs |
| AWS-004 | match | high | Security group opened to the internet | Defense Evasion | T1562.007 Disable or Modify Cloud Firewall |
| AWS-005 | match | high | Administrator policy attached to an identity | Persistence | T1098 Account Manipulation |
| AWS-006 | match | medium | New IAM access key created | Persistence | T1098.001 Additional Cloud Credentials |
| AWS-007 | threshold | medium | Burst of AccessDenied errors (cloud reconnaissance) | Discovery | T1580 Cloud Infrastructure Discovery |
| AWS-008 | threshold | medium | Repeated failed console logins | Credential Access | T1110 Brute Force |
| AUTH-001 | threshold | high | SSH brute force against a single account source | Credential Access | T1110.001 Password Guessing |
| AUTH-002 | threshold | high | SSH password spraying across many usernames | Credential Access | T1110.003 Password Spraying |
| AUTH-003 | match | high | Successful SSH login as root | Initial Access | T1078 Valid Accounts |
| AUTH-004 | sequence | critical | Successful SSH login after repeated failures | Credential Access | T1110 Brute Force |
| AUTH-005 | match | high | Sensitive file accessed via sudo | Credential Access | T1003.008 /etc/passwd and /etc/shadow |
| AUTH-006 | match | critical | Local account created with UID 0 | Persistence | T1136.001 Create Account - Local Account |
| AUTH-007 | match | low | New local account created | Persistence | T1136.001 Create Account - Local Account |
| WEB-001 | match | high | SQL injection attempt in request | Initial Access | T1190 Exploit Public-Facing Application |
| WEB-002 | match | high | Path traversal attempt | Initial Access | T1190 Exploit Public-Facing Application |
| WEB-003 | match | medium | Known vulnerability scanner user agent | Reconnaissance | T1595.002 Vulnerability Scanning |
| WEB-004 | threshold | medium | Directory brute forcing (burst of 404 responses) | Reconnaissance | T1595.003 Wordlist Scanning |
| WEB-005 | match | medium | Access to sensitive files or admin paths | Reconnaissance | T1595.003 Wordlist Scanning |

## Rule types

**match** fires on every event that meets all conditions. Repeated hits for the same
entity (for example the same source IP) are collapsed into one finding to keep alert
volume manageable.

**threshold** groups matching events by `group_by` and fires when a group reaches
`count` events within `window_seconds`. With `distinct`, it counts unique values of a
field instead (for example, unique usernames per IP for password spraying). A burst
produces one finding, not one per event.

**sequence** fires when at least `count` events matching `conditions` are followed by an
event matching `then`, in the same group and within the window. AUTH-004 uses this to
catch a brute force attack that ended in a successful login, which is far more urgent
than failures alone.

## Writing a new rule

```yaml
- id: AUTH-100
  title: SSH login from a cloud scanner range
  source: auth            # auth | web | cloudtrail
  type: match             # match | threshold | sequence
  severity: medium        # info | low | medium | high | critical
  description: Why this matters to an analyst.
  conditions:
    action: {equals: ssh_accepted}
    src_ip: {regex: "^203\\.0\\.113\\."}
  group_by: [src_ip, user]
  mitre: {tactic: Initial Access, technique: T1078 Valid Accounts}
  remediation: What the responder should do next.
```

Available operators: `equals`, `not_equals`, `contains`, `not_contains`, `regex`
(string or list, case-insensitive), `in`, `exists`, `gte`, `lte`.

Add a test case to `tests/test_scenarios.py` (and, if needed, a scenario to
`scripts/generate_sample_data.py`) so the rule is proven to fire and CI keeps it working.

## Tuning notes

Thresholds were chosen to separate the planted attacks from normal office activity in the
sample data. In a real environment they should be tuned against a baseline, and allowlists
(such as approved vulnerability scanners for WEB-003) should be added with `not_equals` or
`not_contains` conditions.
