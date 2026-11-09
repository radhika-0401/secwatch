"""End-to-end: every planted attack in the sample data must be detected."""

from secwatch.detections import DetectionEngine, load_rules
from secwatch.parsers import parse_auth_log, parse_cloudtrail, parse_web_log

EXPECTED = {
    "AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "AUTH-005", "AUTH-006", "AUTH-007",
    "WEB-001", "WEB-002", "WEB-003", "WEB-004", "WEB-005",
    "AWS-001", "AWS-002", "AWS-003", "AWS-004", "AWS-005", "AWS-006", "AWS-007", "AWS-008",
}


def run_all(samples, rules_dir):
    events = (parse_auth_log(samples / "auth.log", year=2026) + parse_web_log(samples / "access.log")
              + parse_cloudtrail(samples / "cloudtrail.json"))
    return DetectionEngine(load_rules(rules_dir)).run(events)


def test_all_scenarios_detected(samples, rules_dir):
    fired = {f.rule_id for f in run_all(samples, rules_dir)}
    assert EXPECTED <= fired, f"missed: {EXPECTED - fired}"


def test_no_false_positives_on_office_users(samples, rules_dir):
    office = {"198.51.100.10", "198.51.100.11"}
    noisy = [f for f in run_all(samples, rules_dir)
             if f.category == "detection" and any(ip in f.entity for ip in office) and f.rule_id != "AWS-001"]
    assert noisy == []


def test_brute_force_success_attributed_to_attacker(samples, rules_dir):
    [f] = [f for f in run_all(samples, rules_dir) if f.rule_id == "AUTH-004"]
    assert "203.0.113.45" in f.entity
    assert f.severity == "critical"
