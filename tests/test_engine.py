from datetime import datetime, timedelta

import pytest

from secwatch.detections import DetectionEngine, Rule, load_rules
from secwatch.models import Event

T0 = datetime(2026, 3, 10, 12, 0, 0)


def failed(ip: str, user: str, seconds: int) -> Event:
    return Event(T0 + timedelta(seconds=seconds), "auth",
                 {"action": "ssh_failed", "src_ip": ip, "user": user}, raw=f"fail {ip} {user}")


def accepted(ip: str, user: str, seconds: int) -> Event:
    return Event(T0 + timedelta(seconds=seconds), "auth",
                 {"action": "ssh_accepted", "src_ip": ip, "user": user, "auth_method": "password"}, raw="ok")


def threshold_rule(**kw) -> Rule:
    base = dict(id="T-1", title="t", source="auth", severity="high", description="d", type="threshold",
                conditions={"action": {"equals": "ssh_failed"}}, group_by=["src_ip"], count=5, window_seconds=60)
    base.update(kw)
    return Rule(**base)


def test_threshold_fires_once_per_burst():
    events = [failed("1.1.1.1", "root", i) for i in range(20)]
    findings = DetectionEngine([threshold_rule()]).run(events)
    assert len(findings) == 1
    assert findings[0].count == 20


def test_threshold_respects_window():
    # 5 failures spread over 10 minutes should not fire with a 60s window.
    events = [failed("1.1.1.1", "root", i * 120) for i in range(5)]
    assert DetectionEngine([threshold_rule()]).run(events) == []


def test_threshold_groups_separately():
    events = [failed("1.1.1.1", "a", i) for i in range(5)] + [failed("2.2.2.2", "a", i) for i in range(4)]
    findings = DetectionEngine([threshold_rule()]).run(events)
    assert [f.entity for f in findings] == ["src_ip=1.1.1.1"]


def test_distinct_counting():
    rule = threshold_rule(distinct="user", count=3)
    same_user = [failed("1.1.1.1", "root", i) for i in range(10)]
    many_users = [failed("2.2.2.2", f"u{i}", i) for i in range(3)]
    findings = DetectionEngine([rule]).run(same_user + many_users)
    assert [f.entity for f in findings] == ["src_ip=2.2.2.2"]


def test_sequence_failures_then_success():
    rule = Rule(id="S-1", title="s", source="auth", severity="critical", description="d", type="sequence",
                conditions={"action": {"equals": "ssh_failed"}}, then={"action": {"equals": "ssh_accepted"}},
                group_by=["src_ip"], count=3, window_seconds=300)
    events = [failed("1.1.1.1", "deploy", i) for i in range(5)] + [accepted("1.1.1.1", "deploy", 10)]
    # A legitimate user with a single typo must not trigger.
    events += [failed("9.9.9.9", "alice", 0), accepted("9.9.9.9", "alice", 5)]
    findings = DetectionEngine([rule]).run(events)
    assert len(findings) == 1
    assert findings[0].entity == "src_ip=1.1.1.1"


def test_match_operators():
    rule = Rule(id="M-1", title="m", source="web", severity="low", description="d",
                conditions={"path": {"regex": ["union\\s+select"]}, "status": {"in": [200, 500]}})
    hit = Event(T0, "web", {"path": "/x?q=UNION SELECT 1", "status": 200})
    miss = Event(T0, "web", {"path": "/x?q=UNION SELECT 1", "status": 404})
    assert rule.matches(hit) and not rule.matches(miss)


def test_invalid_operator_rejected():
    with pytest.raises(ValueError):
        Rule(id="X", title="x", source="auth", severity="low", description="d", conditions={"a": {"bogus": 1}})


def test_bundled_rules_load(rules_dir):
    rules = load_rules(rules_dir)
    assert len(rules) >= 20
    assert all(r.mitre_technique for r in rules), "every rule should map to MITRE ATT&CK"
