"""Scan a Terraform plan (``terraform show -json plan.out``) for AWS misconfigurations.

Scanning the plan instead of raw HCL means variables, locals, and modules are
already resolved, so the checks see the values Terraform will actually deploy.
This lets teams catch problems in CI before anything reaches the cloud.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from secwatch.models import Finding

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _iter_resources(module: dict[str, Any]) -> Iterator[dict[str, Any]]:
    yield from module.get("resources", []) or []
    for child in module.get("child_modules", []) or []:
        yield from _iter_resources(child)


def _f(rid: str, title: str, sev: str, desc: str, addr: str, fix: str, technique: str = "") -> Finding:
    return Finding(rule_id=rid, title=title, severity=sev, category="iac", description=desc,
                   entity=addr, remediation=fix, mitre_technique=technique)


def _check_security_group(addr: str, v: dict) -> list[Finding]:
    out = []
    for rule in v.get("ingress", []) or []:
        cidrs = set(rule.get("cidr_blocks") or []) | set(rule.get("ipv6_cidr_blocks") or [])
        if not cidrs & OPEN_CIDRS:
            continue
        lo, hi = rule.get("from_port", 0), rule.get("to_port", 0)
        all_ports = rule.get("protocol") in ("-1", "all")
        exposed = [name for port, name in ADMIN_PORTS.items() if all_ports or lo <= port <= hi]
        if exposed:
            out.append(_f("IAC-SG-01", f"{'/'.join(exposed)} open to the internet", "high",
                          f"Ingress {lo}-{hi} allows {sorted(cidrs & OPEN_CIDRS)}.", addr,
                          "Restrict to a known CIDR or use SSM Session Manager / a bastion.",
                          "T1133 External Remote Services"))
        elif all_ports:
            out.append(_f("IAC-SG-02", "All ports open to the internet", "high",
                          "Ingress allows every protocol and port from anywhere.", addr,
                          "Allow only required ports from required sources."))
    return out


def _check_s3_acl(addr: str, v: dict) -> list[Finding]:
    if v.get("acl") in ("public-read", "public-read-write", "authenticated-read"):
        return [_f("IAC-S3-01", "S3 bucket ACL grants public access", "high",
                   f"ACL is '{v.get('acl')}'.", addr, "Use 'private' and serve content through CloudFront with OAC.",
                   "T1530 Data from Cloud Storage")]
    return []


def _check_s3_pab(addr: str, v: dict) -> list[Finding]:
    keys = ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
    off = [k for k in keys if v.get(k) is False]
    if off:
        return [_f("IAC-S3-02", "S3 public access block is not fully enabled", "medium",
                   f"Disabled settings: {', '.join(off)}.", addr, "Set all four public access block settings to true.")]
    return []


def _check_rds(addr: str, v: dict) -> list[Finding]:
    out = []
    if not v.get("storage_encrypted"):
        out.append(_f("IAC-RDS-01", "RDS storage is not encrypted", "high", "storage_encrypted is false or unset.",
                      addr, "Set storage_encrypted = true (requires a new instance for existing databases)."))
    if v.get("publicly_accessible"):
        out.append(_f("IAC-RDS-02", "RDS instance is publicly accessible", "high", "publicly_accessible is true.",
                      addr, "Set publicly_accessible = false and place the database in private subnets."))
    return out


def _check_ebs(addr: str, v: dict) -> list[Finding]:
    if not v.get("encrypted"):
        return [_f("IAC-EBS-01", "EBS volume is not encrypted", "medium", "encrypted is false or unset.", addr,
                   "Set encrypted = true, or enable EBS encryption by default for the account.")]
    return []


def _statements(policy: Any) -> list[dict]:
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            return []
    stmts = (policy or {}).get("Statement", [])
    return stmts if isinstance(stmts, list) else [stmts]


def _check_iam_policy(addr: str, v: dict) -> list[Finding]:
    for st in _statements(v.get("policy")):
        if st.get("Effect") != "Allow":
            continue
        actions = st.get("Action", [])
        resources = st.get("Resource", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = [resources] if isinstance(resources, str) else resources
        if "*" in actions and "*" in resources:
            return [_f("IAC-IAM-01", "IAM policy grants full administrative access", "high",
                       "A statement allows Action '*' on Resource '*'.", addr,
                       "Scope actions and resources to least privilege.", "T1078.004 Cloud Accounts")]
    return []


def _check_cloudtrail(addr: str, v: dict) -> list[Finding]:
    out = []
    if v.get("enable_logging") is False:
        out.append(_f("IAC-CT-01", "CloudTrail logging disabled", "critical", "enable_logging is false.", addr,
                      "Set enable_logging = true.", "T1562.008 Disable or Modify Cloud Logs"))
    if not v.get("enable_log_file_validation"):
        out.append(_f("IAC-CT-02", "CloudTrail log file validation disabled", "medium",
                      "Without validation, log tampering cannot be detected.", addr,
                      "Set enable_log_file_validation = true."))
    if not v.get("is_multi_region_trail"):
        out.append(_f("IAC-CT-03", "CloudTrail is not multi-region", "medium",
                      "Activity in other regions will not be logged.", addr, "Set is_multi_region_trail = true."))
    return out


CHECKS = {
    "aws_security_group": _check_security_group,
    "aws_s3_bucket_acl": _check_s3_acl,
    "aws_s3_bucket_public_access_block": _check_s3_pab,
    "aws_db_instance": _check_rds,
    "aws_ebs_volume": _check_ebs,
    "aws_iam_policy": _check_iam_policy,
    "aws_iam_role_policy": _check_iam_policy,
    "aws_cloudtrail": _check_cloudtrail,
}


def scan_terraform_plan(path: str | Path) -> list[Finding]:
    with open(path, encoding="utf-8") as fh:
        plan = json.load(fh)
    root = (plan.get("planned_values") or {}).get("root_module") or {}
    findings: list[Finding] = []
    for res in _iter_resources(root):
        check = CHECKS.get(res.get("type", ""))
        if check:
            findings.extend(check(res.get("address", res.get("name", "?")), res.get("values") or {}))
    return findings
