"""Read-only Linux hardening checks aligned with CIS Benchmark recommendations.

Every check reads configuration files under ``root`` (default ``/``), so the same
code can audit a live host, a mounted disk image, or a container filesystem.
Nothing is modified.
"""

from __future__ import annotations

import stat
from collections.abc import Callable
from pathlib import Path

from secwatch.models import Finding

CIS_REF = "CIS Distribution Independent Linux Benchmark"


def _read(root: Path, rel: str) -> str | None:
    p = root / rel.lstrip("/")
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return None


def _sshd_options(text: str) -> dict[str, str]:
    """Parse sshd_config. The first value for a keyword wins, matching OpenSSH."""
    opts: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.lower().startswith("match "):
            break  # Match blocks apply conditionally; stop at the global section.
        parts = line.split(None, 1)
        if len(parts) == 2:
            opts.setdefault(parts[0].lower(), parts[1].strip())
    return opts


def _finding(cid: str, title: str, sev: str, desc: str, entity: str, fix: str, evidence: str = "") -> Finding:
    return Finding(
        rule_id=cid,
        title=title,
        severity=sev,
        category="hardening",
        description=f"{desc} (Reference: {CIS_REF})",
        entity=entity,
        evidence=[evidence] if evidence else [],
        remediation=fix,
    )


# Each check returns a list of findings (empty means pass).
def check_ssh(root: Path) -> list[Finding]:
    text = _read(root, "/etc/ssh/sshd_config")
    path = "/etc/ssh/sshd_config"
    if text is None:
        return []
    opts = _sshd_options(text)
    out = []
    # OpenSSH defaults are used when an option is not set.
    expectations = [
        ("permitrootlogin", {"no"}, "prohibit-password", "HARD-SSH-01", "SSH root login is not disabled", "high"),
        ("passwordauthentication", {"no"}, "yes", "HARD-SSH-02", "SSH password authentication is enabled", "medium"),
        ("permitemptypasswords", {"no"}, "no", "HARD-SSH-03", "SSH permits empty passwords", "critical"),
        ("x11forwarding", {"no"}, "no", "HARD-SSH-04", "SSH X11 forwarding is enabled", "low"),
    ]
    for key, good, default, cid, title, sev in expectations:
        val = opts.get(key, default).lower()
        if val not in good:
            out.append(_finding(cid, title, sev, f"{key} is '{val}'.", path,
                                f"Set '{key} {sorted(good)[0]}' in {path} and restart sshd.", f"{key} {val}"))
    tries = opts.get("maxauthtries", "6")
    if tries.isdigit() and int(tries) > 4:
        out.append(_finding("HARD-SSH-05", "SSH MaxAuthTries is too high", "low",
                            f"MaxAuthTries is {tries}; 4 or fewer is recommended.", path,
                            f"Set 'MaxAuthTries 4' in {path}.", f"MaxAuthTries {tries}"))
    return out


def check_uid_zero(root: Path) -> list[Finding]:
    text = _read(root, "/etc/passwd")
    if text is None:
        return []
    out = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 3 and parts[2] == "0" and parts[0] != "root":
            out.append(_finding("HARD-ACCT-01", "Non-root account with UID 0", "critical",
                                f"Account '{parts[0]}' has UID 0 and full root privileges.", "/etc/passwd",
                                "Remove the account or assign it a unique non-zero UID.", line))
    return out


def check_empty_passwords(root: Path) -> list[Finding]:
    text = _read(root, "/etc/shadow")
    if text is None:
        return []
    out = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[1] == "":
            out.append(_finding("HARD-ACCT-02", "Account with an empty password", "critical",
                                f"Account '{parts[0]}' can log in without a password.", "/etc/shadow",
                                f"Lock the account with 'passwd -l {parts[0]}' or set a strong password.",
                                f"{parts[0]}:<empty>"))
    return out


def check_password_aging(root: Path) -> list[Finding]:
    text = _read(root, "/etc/login.defs")
    if text is None:
        return []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "PASS_MAX_DAYS" and parts[1].isdigit() and int(parts[1]) > 365:
            return [_finding("HARD-ACCT-03", "Password expiration too long", "low",
                             f"PASS_MAX_DAYS is {parts[1]}; 365 or fewer is recommended.", "/etc/login.defs",
                             "Set PASS_MAX_DAYS to 365 or less in /etc/login.defs.", line)]
    return []


def check_file_permissions(root: Path) -> list[Finding]:
    targets = {"/etc/shadow": 0o640, "/etc/gshadow": 0o640, "/etc/passwd": 0o644, "/etc/ssh/sshd_config": 0o600}
    out = []
    for rel, max_mode in targets.items():
        p = root / rel.lstrip("/")
        if not p.exists():
            continue
        mode = stat.S_IMODE(p.stat().st_mode)
        if mode & ~max_mode:
            sev = "high" if "shadow" in rel else "medium"
            out.append(_finding("HARD-PERM-01", f"Permissions on {rel} are too permissive", sev,
                                f"Mode is {oct(mode)}; expected {oct(max_mode)} or stricter.", rel,
                                f"Run 'chmod {oct(max_mode)[2:]} {rel}'.", f"{rel} {oct(mode)}"))
    return out


CHECKS: list[Callable[[Path], list[Finding]]] = [
    check_ssh,
    check_uid_zero,
    check_empty_passwords,
    check_password_aging,
    check_file_permissions,
]


def run_hardening_checks(root: str | Path = "/") -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []
    for check in CHECKS:
        findings.extend(check(root))
    return findings
