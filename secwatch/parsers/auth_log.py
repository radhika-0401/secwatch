"""Parser for Linux /var/log/auth.log (sshd, sudo, useradd)."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from secwatch.models import Event

LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-\.]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
SSH_FAILED_RE = re.compile(
    r"Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>[\d\.a-fA-F:]+)"
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d\.a-fA-F:]+)"
)
SUDO_RE = re.compile(r"^\s*(?P<user>\S+)\s*:.*?USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.+)$")
USERADD_RE = re.compile(r"new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+)")


def _parse_line(line: str, year: int) -> Event | None:
    m = LINE_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(f"{year} {m['month']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

    msg, proc = m["msg"], m["proc"]
    fields: dict = {"host": m["host"], "process": proc, "message": msg}

    if proc == "sshd":
        if fm := SSH_FAILED_RE.search(msg):
            fields.update(
                action="ssh_failed",
                user=fm["user"],
                src_ip=fm["ip"],
                auth_method=fm["method"],
                invalid_user=bool(fm["invalid"]),
            )
        elif am := SSH_ACCEPTED_RE.search(msg):
            fields.update(
                action="ssh_accepted", user=am["user"], src_ip=am["ip"], auth_method=am["method"]
            )
        else:
            fields["action"] = "ssh_other"
    elif proc == "sudo" and (sm := SUDO_RE.match(msg)):
        fields.update(
            action="sudo", user=sm["user"], target_user=sm["target"], command=sm["cmd"].strip()
        )
    elif proc == "useradd" and (um := USERADD_RE.search(msg)):
        fields.update(action="user_created", user=um["user"], uid=int(um["uid"]))
    else:
        fields["action"] = "other"

    return Event(timestamp=ts, source="auth", fields=fields, raw=line)


def parse_auth_log(path: str | Path, year: int | None = None) -> list[Event]:
    """Parse an auth.log file. Syslog lines omit the year, so it can be supplied."""
    year = year or datetime.now().year
    events = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line and (ev := _parse_line(line, year)):
                events.append(ev)
    return events
