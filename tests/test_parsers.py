import json

from secwatch.parsers import parse_auth_log, parse_cloudtrail, parse_web_log


def test_auth_failed_invalid_user(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("Mar 10 13:55:36 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 54321 ssh2\n")
    [ev] = parse_auth_log(log, year=2026)
    assert ev.get("action") == "ssh_failed"
    assert ev.get("user") == "admin"
    assert ev.get("src_ip") == "203.0.113.5"
    assert ev.get("invalid_user") is True
    assert ev.timestamp.year == 2026


def test_auth_sudo_and_useradd(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Mar 10 14:00:01 web01 sudo[99]:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow\n"
        "Mar 10 14:01:01 web01 useradd[100]: new user: name=evil, UID=0, GID=0, home=/root, shell=/bin/bash\n"
        "this line is garbage and should be skipped\n"
    )
    sudo, add = parse_auth_log(log, year=2026)
    assert sudo.get("action") == "sudo" and sudo.get("command") == "/bin/cat /etc/shadow"
    assert add.get("action") == "user_created" and add.get("uid") == 0


def test_web_log_decodes_payloads(tmp_path):
    log = tmp_path / "access.log"
    log.write_text('192.0.2.1 - - [10/Mar/2026:10:00:00 +0000] "GET /p?id=1%20UNION%20SELECT HTTP/1.1" 200 512 "-" "sqlmap/1.8"\n')
    [ev] = parse_web_log(log)
    assert ev.get("status") == 200
    assert "UNION SELECT" in ev.get("path_decoded")
    assert ev.get("user_agent") == "sqlmap/1.8"


def test_cloudtrail_fields(tmp_path):
    path = tmp_path / "ct.json"
    path.write_text(json.dumps({"Records": [{
        "eventTime": "2026-03-10T10:00:00Z", "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
        "sourceIPAddress": "203.0.113.9", "userIdentity": {"type": "IAMUser", "userName": "bob", "arn": "arn:x"},
        "additionalEventData": {"MFAUsed": "No"}, "responseElements": {"ConsoleLogin": "Success"},
    }]}))
    [ev] = parse_cloudtrail(path)
    assert ev.get("user") == "bob"
    assert ev.get("mfa_used") == "No"
    assert ev.get("login_result") == "Success"


def test_sample_files_parse(samples):
    assert len(parse_auth_log(samples / "auth.log", year=2026)) > 100
    assert len(parse_web_log(samples / "access.log")) > 300
    assert len(parse_cloudtrail(samples / "cloudtrail.json")) > 50
