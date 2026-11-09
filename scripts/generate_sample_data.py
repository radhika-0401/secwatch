"""Generate realistic, deterministic sample logs containing known attack scenarios.

All IP addresses come from the RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) and all account IDs are fake, so nothing
here refers to a real system.

Run:  python scripts/generate_sample_data.py
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(1337)
OUT = Path(__file__).resolve().parent.parent / "sample_data"
BASE = datetime(2026, 3, 10, 8, 0, 0)
HOST = "web01"

NORMAL_USERS = ["alice", "bob", "carol", "deploy"]
OFFICE_IPS = ["198.51.100.10", "198.51.100.11", "198.51.100.12"]
BRUTE_IP = "203.0.113.45"     # brute-forces 'deploy' and eventually succeeds
SPRAY_IP = "203.0.113.77"     # sprays common usernames
SCAN_IP = "192.0.2.200"       # web scanner
SQLI_IP = "192.0.2.150"       # SQL injection attempts
ATTACKER_CLOUD_IP = "203.0.113.99"


def syslog(ts: datetime, proc: str, msg: str, pid: int | None = None) -> str:
    pid = pid or random.randint(1000, 30000)
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {HOST} {proc}[{pid}]: {msg}"


def gen_auth() -> list[str]:
    lines: list[tuple[datetime, str]] = []
    # Normal activity throughout the day
    for i in range(60):
        ts = BASE + timedelta(minutes=random.randint(0, 600))
        user, ip = random.choice(NORMAL_USERS[:3]), random.choice(OFFICE_IPS)
        lines.append((ts, syslog(ts, "sshd", f"Accepted publickey for {user} from {ip} port {random.randint(40000, 65000)} ssh2")))
        if i % 15 == 0:  # occasional typo
            t2 = ts - timedelta(seconds=20)
            lines.append((t2, syslog(t2, "sshd", f"Failed password for {user} from {ip} port {random.randint(40000, 65000)} ssh2")))

    # Scenario 1: brute force against 'deploy' that succeeds
    t = BASE + timedelta(hours=2, minutes=13)
    for _ in range(40):
        t += timedelta(seconds=random.randint(2, 6))
        lines.append((t, syslog(t, "sshd", f"Failed password for deploy from {BRUTE_IP} port {random.randint(40000, 65000)} ssh2")))
    t += timedelta(seconds=4)
    lines.append((t, syslog(t, "sshd", f"Accepted password for deploy from {BRUTE_IP} port 51022 ssh2")))
    # Post-compromise activity
    t += timedelta(minutes=2)
    lines.append((t, syslog(t, "sudo", "  deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")))
    t += timedelta(minutes=1)
    lines.append((t, syslog(t, "useradd", "new user: name=sysupdate, UID=0, GID=0, home=/root, shell=/bin/bash")))
    t += timedelta(minutes=1)
    lines.append((t, syslog(t, "sudo", "  deploy : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/vi /root/.ssh/authorized_keys")))

    # Scenario 2: password spraying across many usernames
    t = BASE + timedelta(hours=5)
    for user in ["admin", "test", "oracle", "postgres", "ubuntu", "git", "jenkins", "support", "guest"]:
        t += timedelta(seconds=random.randint(10, 30))
        lines.append((t, syslog(t, "sshd", f"Failed password for invalid user {user} from {SPRAY_IP} port {random.randint(40000, 65000)} ssh2")))

    # Scenario 3: someone logs in directly as root from the office
    t = BASE + timedelta(hours=7, minutes=42)
    lines.append((t, syslog(t, "sshd", f"Accepted publickey for root from {OFFICE_IPS[2]} port 60111 ssh2")))

    # Benign admin account creation
    t = BASE + timedelta(hours=8)
    lines.append((t, syslog(t, "useradd", "new user: name=dave, UID=1005, GID=1005, home=/home/dave, shell=/bin/bash")))
    return [line for _, line in sorted(lines)]


def web(ts: datetime, ip: str, method: str, path: str, status: int, ua: str, size: int | None = None) -> str:
    size = size if size is not None else random.randint(200, 9000)
    return f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def gen_web() -> list[str]:
    browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
    pages = ["/", "/products", "/products/42", "/cart", "/login", "/static/app.js", "/static/style.css", "/api/items?page=2"]
    lines: list[tuple[datetime, str]] = []
    for _ in range(300):
        ts = BASE + timedelta(seconds=random.randint(0, 36000))
        ip = f"198.51.100.{random.randint(20, 120)}"
        lines.append((ts, web(ts, ip, "GET", random.choice(pages), 200, browser)))

    # Scenario: content discovery with a scanner
    t = BASE + timedelta(hours=3)
    for p in ["/admin", "/backup", "/old", "/test", "/dev", "/api/v0", "/config", "/db", "/uploads", "/tmp",
              "/private", "/logs", "/staging", "/beta", "/hidden", "/secret", "/install", "/setup", "/portal",
              "/console", "/manager", "/debug", "/shell", "/cgi-bin/test"]:
        t += timedelta(seconds=2)
        lines.append((t, web(t, SCAN_IP, "GET", p, 404, "Nikto/2.5.0", 196)))
    for p, code in [("/.env", 403), ("/.git/config", 403), ("/wp-admin/", 301), ("/server-status", 403)]:
        t += timedelta(seconds=2)
        lines.append((t, web(t, SCAN_IP, "GET", p, code, "Nikto/2.5.0", 300)))

    # Scenario: SQL injection and path traversal
    t = BASE + timedelta(hours=4, minutes=30)
    payloads = [
        "/products?id=42%27%20OR%20%271%27=%271",
        "/products?id=42%20UNION%20SELECT%20username,password%20FROM%20users--",
        "/products?id=42;%20DROP%20TABLE%20users--",
        "/products?id=42%20AND%20SLEEP(5)",
        "/api/items?sort=(SELECT%20table_name%20FROM%20information_schema.tables)",
    ]
    for p in payloads:
        t += timedelta(seconds=7)
        lines.append((t, web(t, SQLI_IP, "GET", p, random.choice([200, 500]), "sqlmap/1.8#stable (https://sqlmap.org)")))
    for p in ["/download?file=../../../../etc/passwd", "/download?file=..%2F..%2F..%2Fetc%2Fshadow"]:
        t += timedelta(seconds=5)
        lines.append((t, web(t, SQLI_IP, "GET", p, 400, browser)))
    return [line for _, line in sorted(lines)]


def ct(ts: datetime, name: str, source: str, ip: str, identity: dict, params: dict | None = None,
       error: str | None = None, extra: dict | None = None, response: dict | None = None) -> dict:
    rec = {
        "eventVersion": "1.09",
        "userIdentity": identity,
        "eventTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": source,
        "eventName": name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": ip,
        "userAgent": "aws-cli/2.15.0" if name != "ConsoleLogin" else "Mozilla/5.0",
        "requestParameters": params,
        "responseElements": response,
    }
    if error:
        rec["errorCode"] = error
        rec["errorMessage"] = "User is not authorized to perform this operation"
    if extra:
        rec["additionalEventData"] = extra
    return rec


def iam_user(name: str) -> dict:
    return {"type": "IAMUser", "userName": name, "arn": f"arn:aws:iam::111122223333:user/{name}",
            "accountId": "111122223333"}


def gen_cloudtrail() -> dict:
    recs = []
    # Normal activity
    for _ in range(40):
        ts = BASE + timedelta(minutes=random.randint(0, 600))
        user = random.choice(["alice", "bob", "ci-pipeline"])
        name, src = random.choice([("DescribeInstances", "ec2.amazonaws.com"), ("GetObject", "s3.amazonaws.com"),
                                   ("ListBuckets", "s3.amazonaws.com"), ("DescribeDBInstances", "rds.amazonaws.com")])
        recs.append(ct(ts, name, src, random.choice(OFFICE_IPS), iam_user(user)))
    t = BASE + timedelta(hours=1)
    recs.append(ct(t, "ConsoleLogin", "signin.amazonaws.com", OFFICE_IPS[0], iam_user("alice"),
                   extra={"MFAUsed": "Yes"}, response={"ConsoleLogin": "Success"}))

    # Root usage
    t = BASE + timedelta(hours=1, minutes=30)
    root = {"type": "Root", "arn": "arn:aws:iam::111122223333:root", "accountId": "111122223333"}
    recs.append(ct(t, "ConsoleLogin", "signin.amazonaws.com", OFFICE_IPS[1], root,
                   extra={"MFAUsed": "Yes"}, response={"ConsoleLogin": "Success"}))

    # Attack chain with leaked credentials for 'svc-reporting'
    t = BASE + timedelta(hours=6)
    for _ in range(6):
        t += timedelta(seconds=30)
        recs.append(ct(t, "ConsoleLogin", "signin.amazonaws.com", ATTACKER_CLOUD_IP, iam_user("bob"),
                       extra={"MFAUsed": "No"}, response={"ConsoleLogin": "Failure"}))
    t += timedelta(minutes=5)
    stolen = iam_user("svc-reporting")
    for name, src in [("ListUsers", "iam.amazonaws.com"), ("ListRoles", "iam.amazonaws.com"),
                      ("GetAccountAuthorizationDetails", "iam.amazonaws.com"), ("DescribeInstances", "ec2.amazonaws.com"),
                      ("ListSecrets", "secretsmanager.amazonaws.com"), ("DescribeDBInstances", "rds.amazonaws.com"),
                      ("ListFunctions", "lambda.amazonaws.com"), ("GetBucketPolicy", "s3.amazonaws.com"),
                      ("DescribeTrails", "cloudtrail.amazonaws.com"), ("ListAccessKeys", "iam.amazonaws.com")]:
        t += timedelta(seconds=12)
        recs.append(ct(t, name, src, ATTACKER_CLOUD_IP, stolen, error="AccessDenied"))
    t += timedelta(minutes=3)
    recs.append(ct(t, "ConsoleLogin", "signin.amazonaws.com", ATTACKER_CLOUD_IP, iam_user("svc-reporting"),
                   extra={"MFAUsed": "No"}, response={"ConsoleLogin": "Success"}))
    t += timedelta(minutes=2)
    recs.append(ct(t, "CreateAccessKey", "iam.amazonaws.com", ATTACKER_CLOUD_IP, stolen, params={"userName": "svc-reporting"}))
    t += timedelta(minutes=1)
    recs.append(ct(t, "AttachUserPolicy", "iam.amazonaws.com", ATTACKER_CLOUD_IP, stolen,
                   params={"userName": "svc-reporting", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}))
    t += timedelta(minutes=1)
    recs.append(ct(t, "AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", ATTACKER_CLOUD_IP, stolen,
                   params={"groupId": "sg-0abc1234def567890", "ipPermissions": {"items": [
                       {"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
                        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}))
    t += timedelta(minutes=1)
    recs.append(ct(t, "StopLogging", "cloudtrail.amazonaws.com", ATTACKER_CLOUD_IP, stolen,
                   params={"name": "arn:aws:cloudtrail:us-east-1:111122223333:trail/org-trail"}))

    recs.sort(key=lambda r: r["eventTime"])
    return {"Records": recs}


def main() -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "auth.log").write_text("\n".join(gen_auth()) + "\n")
    (OUT / "access.log").write_text("\n".join(gen_web()) + "\n")
    (OUT / "cloudtrail.json").write_text(json.dumps(gen_cloudtrail(), indent=2) + "\n")
    print(f"Sample data written to {OUT}")


if __name__ == "__main__":
    main()
