import os

from secwatch.hardening import run_hardening_checks


def make_root(tmp_path, sshd: str, passwd: str = "root:x:0:0::/root:/bin/bash\n", shadow: str = "root:$6$x:1::::::\n"):
    (tmp_path / "etc" / "ssh").mkdir(parents=True)
    (tmp_path / "etc" / "ssh" / "sshd_config").write_text(sshd)
    (tmp_path / "etc" / "passwd").write_text(passwd)
    (tmp_path / "etc" / "shadow").write_text(shadow)
    os.chmod(tmp_path / "etc" / "ssh" / "sshd_config", 0o600)
    os.chmod(tmp_path / "etc" / "shadow", 0o640)
    os.chmod(tmp_path / "etc" / "passwd", 0o644)
    return tmp_path


SECURE_SSHD = "PermitRootLogin no\nPasswordAuthentication no\nX11Forwarding no\nMaxAuthTries 3\n"


def ids(findings):
    return {f.rule_id for f in findings}


def test_secure_host_passes(tmp_path):
    assert run_hardening_checks(make_root(tmp_path, SECURE_SSHD)) == []


def test_insecure_ssh_detected(tmp_path):
    root = make_root(tmp_path, "PermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding yes\n")
    assert {"HARD-SSH-01", "HARD-SSH-02", "HARD-SSH-04", "HARD-SSH-05"} <= ids(run_hardening_checks(root))


def test_first_sshd_value_wins(tmp_path):
    root = make_root(tmp_path, "PermitRootLogin no\nPermitRootLogin yes\n" + SECURE_SSHD)
    assert "HARD-SSH-01" not in ids(run_hardening_checks(root))


def test_uid0_and_empty_password(tmp_path):
    root = make_root(tmp_path, SECURE_SSHD,
                     passwd="root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\n",
                     shadow="root:$6$x:1::::::\ntoor::1::::::\n")
    assert {"HARD-ACCT-01", "HARD-ACCT-02"} <= ids(run_hardening_checks(root))


def test_world_readable_shadow(tmp_path):
    root = make_root(tmp_path, SECURE_SSHD)
    os.chmod(root / "etc" / "shadow", 0o644)
    assert "HARD-PERM-01" in ids(run_hardening_checks(root))


def test_missing_files_are_skipped(tmp_path):
    assert run_hardening_checks(tmp_path) == []
