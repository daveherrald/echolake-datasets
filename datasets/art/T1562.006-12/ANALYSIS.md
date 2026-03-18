# T1562.006-12: Indicator Blocking — Disable .NET ETW via Environment Variable HKLM Registry - Cmd

## Technique Context

T1562.006 (Indicator Blocking) includes disabling ETW for .NET processes system-wide. While
setting `COMPlus_ETWEnabled=0` in `HKCU\Environment` affects only the current user, setting it
in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` affects every process on
the system — including high-privilege .NET processes and services. This is a more aggressive
variant of the ETW bypass, requiring SYSTEM or Administrator privileges but providing broader
coverage. This test uses `cmd.exe` with `reg.exe` to make the system-wide change:
`REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v COMPlus_ETWEnabled /t REG_SZ /d 0 /f`

## What This Dataset Contains

**Sysmon EID 1 — process creation (28 events, 3 process-create):**
- `cmd.exe /c REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v COMPlus_ETWEnabled /t REG_SZ /d 0 /f` (parent: powershell.exe)
- `reg.exe REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v COMPlus_ETWEnabled /t REG_SZ /d 0 /f` (child of cmd.exe)
- `whoami.exe`

**Sysmon EID 13 — registry value set (1 event):**
```
TargetObject: HKLM\System\CurrentControlSet\Control\Session Manager\Environment\COMPlus_ETWEnabled
Details: 0
Image: C:\Windows\system32\reg.exe
User: NT AUTHORITY\SYSTEM
```
The path distinguishes this from the HKCU variant — the HKLM write affects all users and
services on the machine.

**Security EID 4688 (12 events):** whoami.exe, cmd.exe, reg.exe. SYSTEM context throughout.

**PowerShell EID 4104 (34 events):** ART test framework boilerplate only. No test-specific PowerShell
content.

## What This Dataset Does Not Contain (and Why)

**No Windows registry audit events (EID 4657):** `object_access: none` in the audit policy means
Security log does not capture the registry write directly.

**No System events for environment variable broadcast:** When a registry value changes in the
system environment, Windows should broadcast `WM_SETTINGCHANGE` to running applications. No
events from that broadcast appear in this dataset.

**No downstream effects on .NET processes:** No .NET application is launched post-write to
demonstrate ETW suppression. The test is limited to the write operation itself.

**The HKLM write requires elevated privileges** — this operation would fail without SYSTEM or
Administrator rights, so the SYSTEM execution context is a prerequisite, not an anomaly.

## Assessment

This dataset is the HKLM/system-wide counterpart to T1562.006-10 (HKCU/cmd). The process chain
and execution method are identical; only the registry target path differs. That difference is
critical for detection: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\
COMPlus_ETWEnabled` is a system-wide, persistent change that survives user logon and affects all
.NET processes, making it significantly more impactful than the HKCU variant. The Sysmon EID 13
event captures the full path. Test executed successfully.

## Detection Opportunities Present in This Data

- **Sysmon EID 13 (high-priority):** `TargetObject: HKLM\System\CurrentControlSet\Control\Session Manager\Environment\COMPlus_ETWEnabled` with `Details: 0` — system-wide ETW disable, should be treated as critical
- **Sysmon EID 1:** `reg.exe` with command line containing `COMPlus_ETWEnabled` targeting the HKLM path — requires SYSTEM/admin privileges, making the combination highly suspicious
- **Sysmon EID 1:** `cmd.exe -> reg.exe` chain with `"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"` as the target
- **Security EID 4688:** reg.exe process creation with command-line logging showing `COMPlus_ETWEnabled` and the HKLM path
- **Severity escalation vs. HKCU variant:** A rule matching the HKLM path should be higher severity than the HKCU path because it affects all users and services, not just the current user context
- **Persistence consideration:** HKLM environment variable writes survive reboots and affect new processes indefinitely until removed — this is a persistent defense evasion, not a transient one
