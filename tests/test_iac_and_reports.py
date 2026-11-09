import json

from secwatch.cli import main
from secwatch.iac import scan_terraform_plan


def test_insecure_plan(samples):
    ids = {f.rule_id for f in scan_terraform_plan(samples / "tfplan.json")}
    assert {"IAC-SG-01", "IAC-S3-01", "IAC-S3-02", "IAC-RDS-01", "IAC-RDS-02",
            "IAC-EBS-01", "IAC-IAM-01", "IAC-CT-02", "IAC-CT-03"} <= ids


def test_secure_plan_is_clean(samples):
    assert scan_terraform_plan(samples / "tfplan_secure.json") == []


def test_https_open_to_world_is_allowed(tmp_path):
    plan = {"planned_values": {"root_module": {"resources": [{"address": "aws_security_group.w", "type": "aws_security_group",
            "values": {"ingress": [{"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]}}]}}}
    p = tmp_path / "plan.json"
    p.write_text(json.dumps(plan))
    assert scan_terraform_plan(p) == []


def test_child_modules_scanned(tmp_path):
    plan = {"planned_values": {"root_module": {"child_modules": [{"resources": [
        {"address": "module.db.aws_ebs_volume.x", "type": "aws_ebs_volume", "values": {"encrypted": False}}]}]}}}
    p = tmp_path / "plan.json"
    p.write_text(json.dumps(plan))
    assert [f.entity for f in scan_terraform_plan(p)] == ["module.db.aws_ebs_volume.x"]


def test_cli_writes_all_formats_and_fail_on(samples, tmp_path):
    code = main(["iac", "--plan", str(samples / "tfplan.json"), "-o", str(tmp_path),
                 "-f", "json,md,html,sarif", "--fail-on", "high"])
    assert code == 1
    report = json.loads((tmp_path / "iac.json").read_text())
    assert report["summary"]["total"] == len(report["findings"]) > 0
    sarif = json.loads((tmp_path / "iac.sarif").read_text())
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    assert "<html" in (tmp_path / "iac.html").read_text()
    assert "# SecWatch Security Report" in (tmp_path / "iac.md").read_text()


def test_cli_detect_requires_input():
    assert main(["detect"]) == 2
