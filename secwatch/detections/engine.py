"""A small YAML-driven detection engine (inspired by Sigma).

Two rule types are supported:

* ``match``: every event that satisfies the conditions produces a finding.
* ``threshold``: events that satisfy the conditions are grouped (for example by
  source IP) and a finding fires when a group reaches ``count`` events, or
  ``count`` distinct values of ``distinct``, within ``window_seconds``.
* ``sequence``: at least ``count`` events matching ``conditions`` followed by an
  event matching ``then`` in the same group within ``window_seconds``
  (for example, failed logins followed by a successful one).
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from secwatch.models import Event, Finding

MAX_EVIDENCE = 5
OPERATORS = {"equals", "not_equals", "contains", "not_contains", "regex", "in", "exists", "gte", "lte"}


@dataclass
class Rule:
    id: str
    title: str
    source: str
    severity: str
    description: str
    type: str = "match"
    conditions: dict[str, dict[str, Any]] = field(default_factory=dict)
    then: dict[str, dict[str, Any]] = field(default_factory=dict)
    group_by: list[str] = field(default_factory=list)
    count: int = 1
    window_seconds: int = 300
    distinct: str | None = None
    mitre_tactic: str = ""
    mitre_technique: str = ""
    remediation: str = ""

    def __post_init__(self) -> None:
        if self.type not in ("match", "threshold", "sequence"):
            raise ValueError(f"Rule {self.id}: unknown type '{self.type}'")
        if self.type == "sequence" and not self.then:
            raise ValueError(f"Rule {self.id}: sequence rules need a 'then' block")
        for fname, ops in {**self.conditions, **self.then}.items():
            unknown = set(ops) - OPERATORS
            if unknown:
                raise ValueError(f"Rule {self.id}: unknown operator(s) {unknown} on '{fname}'")
            if "regex" in ops:
                pats = ops["regex"] if isinstance(ops["regex"], list) else [ops["regex"]]
                ops["_compiled"] = [re.compile(p, re.IGNORECASE) for p in pats]

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Rule:
        mitre = d.get("mitre", {}) or {}
        return cls(
            id=d["id"],
            title=d["title"],
            source=d["source"],
            severity=d.get("severity", "medium"),
            description=d.get("description", ""),
            type=d.get("type", "match"),
            conditions=d.get("conditions", {}) or {},
            then=d.get("then", {}) or {},
            group_by=d.get("group_by", []) or [],
            count=int(d.get("count", 1)),
            window_seconds=int(d.get("window_seconds", 300)),
            distinct=d.get("distinct"),
            mitre_tactic=mitre.get("tactic", ""),
            mitre_technique=mitre.get("technique", ""),
            remediation=d.get("remediation", ""),
        )

    # ---- condition evaluation -------------------------------------------------
    def matches(self, event: Event) -> bool:
        if event.source != self.source:
            return False
        return all(_check(event.get(f), ops) for f, ops in self.conditions.items())

    def matches_then(self, event: Event) -> bool:
        if event.source != self.source:
            return False
        return all(_check(event.get(f), ops) for f, ops in self.then.items())


def _check(value: Any, ops: dict[str, Any]) -> bool:
    if "exists" in ops and (value not in (None, "")) != bool(ops["exists"]):
        return False
    if value is None:
        return "exists" in ops and not ops["exists"]
    sval = str(value).lower()
    if "equals" in ops and value != ops["equals"] and sval != str(ops["equals"]).lower():
        return False
    if "not_equals" in ops and (value == ops["not_equals"] or sval == str(ops["not_equals"]).lower()):
        return False
    if "contains" in ops:
        needles = ops["contains"] if isinstance(ops["contains"], list) else [ops["contains"]]
        if not any(str(n).lower() in sval for n in needles):
            return False
    if "not_contains" in ops:
        needles = ops["not_contains"] if isinstance(ops["not_contains"], list) else [ops["not_contains"]]
        if any(str(n).lower() in sval for n in needles):
            return False
    if "_compiled" in ops and not any(p.search(str(value)) for p in ops["_compiled"]):
        return False
    if "in" in ops and value not in ops["in"] and sval not in [str(v).lower() for v in ops["in"]]:
        return False
    try:
        if "gte" in ops and float(value) < float(ops["gte"]):
            return False
        if "lte" in ops and float(value) > float(ops["lte"]):
            return False
    except (TypeError, ValueError):
        return False
    return True


def load_rules(rules_dir: str | Path) -> list[Rule]:
    rules: list[Rule] = []
    seen: set[str] = set()
    for path in sorted(Path(rules_dir).glob("*.y*ml")):
        with open(path, encoding="utf-8") as fh:
            docs = yaml.safe_load(fh) or []
        for d in docs if isinstance(docs, list) else [docs]:
            rule = Rule.from_dict(d)
            if rule.id in seen:
                raise ValueError(f"Duplicate rule id {rule.id} in {path}")
            seen.add(rule.id)
            rules.append(rule)
    return rules


class DetectionEngine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def run(self, events: list[Event]) -> list[Finding]:
        events = sorted(events, key=lambda e: e.timestamp)
        findings: list[Finding] = []
        for rule in self.rules:
            if rule.type == "sequence":
                findings.extend(self._sequence_findings(rule, events))
                continue
            hits = [e for e in events if rule.matches(e)]
            if not hits:
                continue
            if rule.type == "match":
                findings.extend(self._match_findings(rule, hits))
            else:
                findings.extend(self._threshold_findings(rule, hits))
        return findings

    @staticmethod
    def _entity(rule: Rule, event: Event) -> str:
        keys = rule.group_by or ["src_ip", "user"]
        parts = [f"{k}={event.get(k)}" for k in keys if event.get(k) not in (None, "")]
        return ", ".join(parts)

    def _base(self, rule: Rule, events: list[Event], entity: str) -> Finding:
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            category="detection",
            description=rule.description,
            mitre_tactic=rule.mitre_tactic,
            mitre_technique=rule.mitre_technique,
            entity=entity,
            first_seen=events[0].timestamp.isoformat(),
            last_seen=events[-1].timestamp.isoformat(),
            count=len(events),
            evidence=[e.raw[:300] for e in events[:MAX_EVIDENCE]],
            remediation=rule.remediation,
        )

    def _match_findings(self, rule: Rule, hits: list[Event]) -> list[Finding]:
        # Collapse repeated hits for the same entity into one finding to reduce alert noise.
        grouped: dict[str, list[Event]] = defaultdict(list)
        for e in hits:
            grouped[self._entity(rule, e)].append(e)
        return [self._base(rule, evs, ent) for ent, evs in grouped.items()]

    def _threshold_findings(self, rule: Rule, hits: list[Event]) -> list[Finding]:
        window = timedelta(seconds=rule.window_seconds)
        grouped: dict[tuple, list[Event]] = defaultdict(list)
        for e in hits:
            grouped[tuple(e.get(k) for k in rule.group_by)].append(e)

        findings = []
        for key, evs in grouped.items():
            left = 0
            fired_until = -1
            for right in range(len(evs)):
                while evs[right].timestamp - evs[left].timestamp > window:
                    left += 1
                if right <= fired_until:
                    continue
                win = evs[left : right + 1]
                size = len({e.get(rule.distinct) for e in win}) if rule.distinct else len(win)
                if size >= rule.count:
                    # Extend to include the rest of the burst so one attack yields one finding.
                    end = right
                    while end + 1 < len(evs) and evs[end + 1].timestamp - evs[left].timestamp <= window:
                        end += 1
                    burst = evs[left : end + 1]
                    entity = ", ".join(f"{k}={v}" for k, v in zip(rule.group_by, key, strict=True))
                    f = self._base(rule, burst, entity)
                    if rule.distinct:
                        distinct_vals = sorted({str(e.get(rule.distinct)) for e in burst})
                        f.description += f" Distinct {rule.distinct} values: {len(distinct_vals)}."
                    findings.append(f)
                    fired_until = end
        return findings

    def _sequence_findings(self, rule: Rule, events: list[Event]) -> list[Finding]:
        window = timedelta(seconds=rule.window_seconds)
        recent: dict[tuple, list[Event]] = defaultdict(list)
        findings = []
        for e in events:
            key = tuple(e.get(k) for k in rule.group_by)
            if rule.matches(e):
                recent[key].append(e)
            elif rule.matches_then(e):
                prior = [p for p in recent[key] if e.timestamp - p.timestamp <= window]
                if len(prior) >= rule.count:
                    entity = ", ".join(f"{k}={v}" for k, v in zip(rule.group_by, key, strict=True))
                    f = self._base(rule, prior + [e], entity)
                    f.evidence = [p.raw[:300] for p in prior[-3:]] + [e.raw[:300]]
                    f.description += f" {len(prior)} preceding events; success for user '{e.get('user')}'."
                    findings.append(f)
                    recent[key] = []
        return findings
