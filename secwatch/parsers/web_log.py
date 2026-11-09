"""Parser for web server access logs in Apache/Nginx combined format."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote_plus

from secwatch.models import Event

COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)(?: "(?P<referrer>[^"]*)" "(?P<ua>[^"]*)")?'
)


def parse_web_log(path: str | Path) -> list[Event]:
    events = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            m = COMBINED_RE.match(line)
            if not m:
                continue
            try:
                ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
            except ValueError:
                continue
            events.append(
                Event(
                    timestamp=ts,
                    source="web",
                    raw=line,
                    fields={
                        "src_ip": m["ip"],
                        "method": m["method"],
                        "path": m["path"],
                        # Decoded path catches URL-encoded attack payloads.
                        "path_decoded": unquote_plus(m["path"]),
                        "status": int(m["status"]),
                        "bytes": 0 if m["bytes"] == "-" else int(m["bytes"]),
                        "user_agent": m["ua"] or "",
                    },
                )
            )
    return events
