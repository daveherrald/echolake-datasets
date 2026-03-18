# T1562.001-33: Disable or Modify Tools — cmd

## Technique Context

MITRE ATT&CK T1562.001 (Disable or Modify Tools) covers registry modifications that alter security-relevant system behavior. This test replicates a LockBit Black technique that configures Windows automatic logon by writing credentials directly into the registry under `HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon`. Automatic logon allows a system to boot directly to a user's desktop without requiring interactive authentication. Ransomware operators use this to ensure that after a forced reboot (such as one that precedes encryption), the system auto-logs in and the ransomware payload can resume execution without requiring user interaction. The cmd.exe variant uses four sequential `reg add` calls to set `AutoAdminLogon`, `DefaultUserName`, `DefaultDomainName`, and `DefaultPassword`.

## What This Dataset Contains

The dataset captures 6 seconds of telemetry from ACME-WS02 during the LockBit Black autologon configuration test via `cmd.exe` and `reg.exe`.

**Security 4688 — Full four-command `reg add` sequence with embedded credentials:**
```
"cmd.exe" /c reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 1 /f & reg add ... /v DefaultUserName /t REG_SZ /d Administrator /f & reg add ... /v DefaultDomainName /t REG_SZ /d contoso.com /f & reg add ... /v DefaultPassword /t REG_SZ /d password1 /f
```
Individual `reg.exe` invocations are also captured as separate 4688 events:
```
reg  add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 1 /f
reg  add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d Administrator /f
reg  add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName /t REG_SZ /d contoso.com /f
reg  add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d password1 /f
```

**Sysmon EID 1 — Six process creates captured**, including `cmd.exe`, four `reg.exe` invocations, and `whoami.exe`.

**Security 4689 — Exit statuses for all four `reg.exe` processes: `0x0`**, confirming successful registry writes.

**Sysmon EID 7 — Image loads:** PowerShell runtime DLLs, Defender client libraries, and standard system libraries.

**PowerShell 4104 — Script block:** Test framework invocation is logged; the `reg add` commands run via `cmd.exe` and do not appear as additional 4104 blocks.

## What This Dataset Does Not Contain (and Why)

**Registry write events via Sysmon EID 13** — The Winlogon policy key modifications are not captured as Sysmon registry events, consistent with the sysmon-modular configuration not including this path in EID 12/13 include rules. The Security 4688 command lines and `reg.exe` exit statuses are the primary evidence of what was written.

**Logon events showing autologon in effect** — The autologon was configured but the system was not rebooted during the test window, so no automatic logon session is present in the data.

**Credential masking** — The cleartext password `password1` and domain `contoso.com` appear in the Security 4688 command line in plaintext. This is expected behavior: Windows security event logging captures command-line arguments without masking.

**Defender block** — The HKLM Winlogon policy key is not a Tamper Protection-covered path. Defender did not block this sequence, and all four writes succeeded.

## Assessment

This is a **successful execution** dataset. All four `reg.exe` commands exited cleanly (`0x0`), and the complete command line sequence — including the plaintext credential values — is captured across Security 4688 events. This dataset is particularly significant for detection because cleartext credentials appear in process creation audit logs. The pattern of writing `DefaultPassword` to a Winlogon registry key in plaintext is a high-fidelity indicator. The `contoso.com` domain and `Administrator` username are hardcoded ART test defaults and would be replaced with real values in an actual ransomware deployment. The Sysmon include-mode filter captures all `reg.exe` invocations because `reg.exe` is in the sysmon-modular LOLBin list.

## Detection Opportunities Present in This Data

- **`reg.exe` writing `DefaultPassword` to Winlogon key** (Security 4688 / Sysmon EID 1): Writing a value named `DefaultPassword` to any registry path is a high-confidence indicator of autologon configuration. The `/d` parameter value is the cleartext credential.
- **`AutoAdminLogon = 1` in Winlogon policy path**: This specific registry key/value combination is directly associated with LockBit Black and other ransomware families that configure autologon pre-encryption.
- **Four sequential `reg add` commands sharing the same base path**: The pattern of multiple `reg add` calls to `Winlogon` within seconds from a `cmd.exe` parent is a strong behavioral indicator.
- **`powershell.exe` → `cmd.exe` → `reg.exe` chain with Winlogon target**: Correlating the process parent chain with the target registry key path tightens detection specificity and reduces false positives from legitimate `reg.exe` usage.
- **Credential exposure in event logs**: Security 4688 with `DefaultPassword` in the command line can be correlated with credential exposure monitoring pipelines.
