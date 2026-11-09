"""Parser for AWS CloudTrail logs (JSON with a top-level "Records" list)."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from secwatch.models import Event


def parse_cloudtrail(path: str | Path) -> list[Event]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    records = data.get("Records", data if isinstance(data, list) else [])

    events = []
    for rec in records:
        try:
            ts = datetime.strptime(rec["eventTime"], "%Y-%m-%dT%H:%M:%SZ")
        except (KeyError, ValueError):
            continue
        identity = rec.get("userIdentity", {}) or {}
        extra = rec.get("additionalEventData", {}) or {}
        response = rec.get("responseElements", {}) or {}
        events.append(
            Event(
                timestamp=ts,
                source="cloudtrail",
                raw=json.dumps(rec),
                fields={
                    "event_name": rec.get("eventName", ""),
                    "event_source": rec.get("eventSource", ""),
                    "region": rec.get("awsRegion", ""),
                    "src_ip": rec.get("sourceIPAddress", ""),
                    "user_agent": rec.get("userAgent", ""),
                    "identity_type": identity.get("type", ""),
                    "user_arn": identity.get("arn", ""),
                    "user": identity.get("userName") or identity.get("type", ""),
                    "mfa_used": extra.get("MFAUsed", ""),
                    "login_result": (response.get("ConsoleLogin") if isinstance(response, dict) else "") or "",
                    "error_code": rec.get("errorCode", ""),
                    # Serialized parameters let rules match on nested values such as CIDRs.
                    "request": json.dumps(rec.get("requestParameters") or {}),
                },
            )
        )
    return events
