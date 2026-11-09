"""Shared data models for events and findings."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Event:
    """A normalized security event produced by a parser."""

    timestamp: datetime
    source: str  # "auth", "web", or "cloudtrail"
    fields: dict[str, Any]
    raw: str = ""

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)


@dataclass
class Finding:
    """A security finding produced by a detection rule, hardening check, or IaC check."""

    rule_id: str
    title: str
    severity: str
    category: str  # "detection", "hardening", or "iac"
    description: str
    mitre_tactic: str = ""
    mitre_technique: str = ""
    entity: str = ""  # what the finding is about: an IP, user, file, or resource
    first_seen: str = ""
    last_seen: str = ""
    count: int = 1
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity.lower(), 0)
