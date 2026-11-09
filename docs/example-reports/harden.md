# SecWatch Security Report

Generated 2026-11-05 21:38 UTC · 9 findings

| Severity | Count |
|---|---|
| Critical | 2 |
| High | 2 |
| Medium | 2 |
| Low | 3 |
| Info | 0 |

## Findings

| Severity | ID | Title | Entity | Count | ATT&CK |
|---|---|---|---|---|---|
| CRITICAL | HARD-ACCT-01 | Non-root account with UID 0 | `/etc/passwd` | 1 |  |
| CRITICAL | HARD-ACCT-02 | Account with an empty password | `/etc/shadow` | 1 |  |
| HIGH | HARD-PERM-01 | Permissions on /etc/shadow are too permissive | `/etc/shadow` | 1 |  |
| HIGH | HARD-SSH-01 | SSH root login is not disabled | `/etc/ssh/sshd_config` | 1 |  |
| MEDIUM | HARD-PERM-01 | Permissions on /etc/ssh/sshd_config are too permissive | `/etc/ssh/sshd_config` | 1 |  |
| MEDIUM | HARD-SSH-02 | SSH password authentication is enabled | `/etc/ssh/sshd_config` | 1 |  |
| LOW | HARD-ACCT-03 | Password expiration too long | `/etc/login.defs` | 1 |  |
| LOW | HARD-SSH-04 | SSH X11 forwarding is enabled | `/etc/ssh/sshd_config` | 1 |  |
| LOW | HARD-SSH-05 | SSH MaxAuthTries is too high | `/etc/ssh/sshd_config` | 1 |  |

## Details

### [CRITICAL] HARD-ACCT-01: Non-root account with UID 0

Account 'sysupdate' has UID 0 and full root privileges. (Reference: CIS Distribution Independent Linux Benchmark)

- **Entity:** `/etc/passwd`
- **Remediation:** Remove the account or assign it a unique non-zero UID.

```
sysupdate:x:0:0::/root:/bin/bash
```

### [CRITICAL] HARD-ACCT-02: Account with an empty password

Account 'sysupdate' can log in without a password. (Reference: CIS Distribution Independent Linux Benchmark)

- **Entity:** `/etc/shadow`
- **Remediation:** Lock the account with 'passwd -l sysupdate' or set a strong password.

```
sysupdate:<empty>
```

### [HIGH] HARD-PERM-01: Permissions on /etc/shadow are too permissive

Mode is 0o644; expected 0o640 or stricter. (Reference: CIS Distribution Independent Linux Benchmark)

- **Entity:** `/etc/shadow`
- **Remediation:** Run 'chmod 640 /etc/shadow'.

```
/etc/shadow 0o644
```

### [HIGH] HARD-SSH-01: SSH root login is not disabled

permitrootlogin is 'yes'. (Reference: CIS Distribution Independent Linux Benchmark)

- **Entity:** `/etc/ssh/sshd_config`
- **Remediation:** Set 'permitrootlogin no' in /etc/ssh/sshd_config and restart sshd.

```
permitrootlogin yes
```

### [MEDIUM] HARD-PERM-01: Permissions on /etc/ssh/sshd_config are too permissive

Mode is 0o644; expected 0o600 or stricter. (Reference: CIS Distribution Independent Linux Benchmark)

- **Entity:** `/etc/ssh/sshd_config`
- **Remediation:** Run 'chmod 600 /etc/ssh/sshd_config'.

```
/etc/ssh/sshd_config 0o644
```

### [MEDIUM] HARD-SSH-02: SSH password authentication is enabled

passwordauthentication is 'yes'. (Reference: CIS Distribution Independent Linux Benchmark)

- **Entity:** `/etc/ssh/sshd_config`
- **Remediation:** Set 'passwordauthentication no' in /etc/ssh/sshd_config and restart sshd.

```
passwordauthentication yes
```

### [LOW] HARD-ACCT-03: Password expiration too long

PASS_MAX_DAYS is 99999; 365 or fewer is recommended. (Reference: CIS Distribution Independent Linux Benchmark)

- **Entity:** `/etc/login.defs`
- **Remediation:** Set PASS_MAX_DAYS to 365 or less in /etc/login.defs.

```
PASS_MAX_DAYS   99999
```

### [LOW] HARD-SSH-04: SSH X11 forwarding is enabled

x11forwarding is 'yes'. (Reference: CIS Distribution Independent Linux Benchmark)

- **Entity:** `/etc/ssh/sshd_config`
- **Remediation:** Set 'x11forwarding no' in /etc/ssh/sshd_config and restart sshd.

```
x11forwarding yes
```

### [LOW] HARD-SSH-05: SSH MaxAuthTries is too high

MaxAuthTries is 6; 4 or fewer is recommended. (Reference: CIS Distribution Independent Linux Benchmark)

- **Entity:** `/etc/ssh/sshd_config`
- **Remediation:** Set 'MaxAuthTries 4' in /etc/ssh/sshd_config.

```
MaxAuthTries 6
```
