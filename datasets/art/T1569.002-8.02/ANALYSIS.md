# T1569.002-8: Service Execution — PsExec Tool Execution From Suspicious Locations

## Technique Context

MITRE ATT&CK T1569.002 (Service Execution) covers adversary use of the Windows Service
Control Manager to execute programs. PsExec (Sysinternals) functions by copying itself to
the target, installing a service (`PSEXESVC`), and executing commands through it. This test
focuses on a specific detection pattern: PsExec executed from a non-standard, user-writable
location (`C:\Users\Public\Temp\`).

Executing legitimate administrative tools from user-writable directories rather than
`C:\Windows\System32\` or controlled administrative paths is a common lateral movement
tactic. Adversaries frequently stage remote execution tools in directories like `%TEMP%`,
`C:\Users\Public\`, or created directories under `C:\Users\` to avoid path-based detections.
The test invokes `PsExec.exe -i -s cmd -accepteula` locally under SYSTEM, simulating a
scenario where the attacker has already dropped PsExec to a staging directory and is testing
execution.

In the defended variant, Windows Defender blocked PsExec before it could install the
`PSEXESVC` service or create the characteristic `\PSEXESVC` named pipe. The PowerShell
test framework command line with the staging path `C:\Users\Public\Temp\` was visible in Sysmon
EID 1. This undefended dataset removes Defender from the equation.

## What This Dataset Contains

The dataset spans approximately 4 seconds (17:42:18–17:42:22 UTC) and contains 154 total
events across four channels, the richest collection among the T1569.002 tests.

**Security channel (21 events) — EIDs 4688, 4689, 4624, 4627, 4672, 4702, 4703:**

**Pre-flight `whoami.exe`:**
```
New Process Name: C:\Windows\System32\whoami.exe
Process Command Line: "C:\Windows\system32\whoami.exe"
Exit Status: 0x0
```

**`taskhostw.exe` task host launch (OS background):**
```
New Process Name: C:\Windows\System32\taskhostw.exe
Process Command Line: taskhostw.exe
Creator Process Name: C:\Windows\System32\svchost.exe
```
This is Windows Task Scheduler launching `taskhostw.exe` for a scheduled task — OS
background activity coincident with the test window, not related to PsExec.

**Child `powershell.exe` with PsExec staging command:**
```
New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process Command Line: "powershell.exe" & {cd ...
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Exit Status: 0x0
```
The `{cd ` prefix is consistent with `{cd C:\Users\Public\Temp\ .\PsExec.exe -i -s cmd
-accepteula}` — the staging directory path and PsExec invocation. The `0x0` exit indicates
the PowerShell block completed without error.

**Service logon events:**

EID 4624 (Logon Type 5 — Service):
```
Account Name: SYSTEM
Account Domain: NT AUTHORITY
Logon Type: 5
Elevated Token: Yes
Impersonation Level: Impersonation
Creator Process Name: C:\Windows\System32\services.exe
```

EID 4672 (Special privileges assigned):
```
Account Name: SYSTEM
Privileges: SeAssignPrimaryTokenPrivilege, SeTcbPrivilege, SeSecurityPrivilege,
            SeTakeOwnershipPrivilege, SeLoadDriverPrivilege, SeBackupPrivilege,
            SeRestorePrivilege, SeDebugPrivilege, SeAuditPrivilege,
            SeSystemEnvironmentPrivilege, SeImpersonatePrivilege,
            SeDelegateSessionUserImpersonatePrivilege
```

EID 4627 (Group membership information):
```
Logon Type: 5
Account Name: SYSTEM
Group Membership: Administrators, Everyone, Authenticated Users, High Mandatory Level
```

These service logon events fire when the Windows SCM establishes a service context —
consistent with PsExec (or another service) being installed and starting. Unlike the
defended variant where these events did not appear, their presence here indicates that
PsExec progressed further into the service installation sequence before the test window
closed.

EID 4702 (Scheduled task updated):
`\Microsoft\Windows\Flighting\OneSettings\RefreshCache` — OS background OneSettings task
update, unrelated to PsExec.

**`sppsvc.exe` (Software Protection service):**
```
New Process Name: C:\Windows\System32\sppsvc.exe
Creator Process Name: C:\Windows\System32\services.exe
```
This is the Windows Software Protection service starting — a normal OS background service
launch triggered by the services.exe activity during PsExec's service operations.

**PowerShell channel (125 events) — EIDs 4104, 4103:**

The 121 EID 4104 events are ART test framework boilerplate. EID 4103 records `Set-ExecutionPolicy
Bypass` and `Write-Host "DONE"`. The PsExec invocation runs inside the child `powershell.exe`
process (`& {cd C:\Users\Public\Temp\ .\PsExec.exe -i -s cmd -accepteula}`).

**TaskScheduler channel (7 events) — EIDs 100, 102, 107, 129, 140, 200, 201:**

A complete task lifecycle for `\Microsoft\Windows\Flighting\OneSettings\RefreshCache`:
- EID 107: task launched due to time trigger
- EID 129: `taskhostw.exe` launched with process ID 17776
- EID 100: task started for `NT AUTHORITY\SYSTEM`
- EID 200: action launched
- EID 140: task updated by `ACME\ACME-WS06$`
- EID 102: task completed successfully
- EID 201: action completed with return code 0

This is the Windows OneSettings cache refresh task running on its normal schedule. It is
real OS background activity that fell within the test collection window.

**Application channel (1 event) — EID 16394:**
`Offline downlevel migration succeeded.` — Windows component servicing background activity.

## What This Dataset Does Not Contain

**No `PsExec.exe` process creation event.** Security EID 4688 does not capture `PsExec.exe`
running as a child of `powershell.exe`. This could indicate Defender (disabled globally but
not necessarily in all forms) or a different execution barrier prevented PsExec from reaching
the process creation stage, or the PsExec process was not captured by the audit scope.

**No PSEXESVC service or named pipe events.** The defended dataset's analysis noted Defender
blocked the PSEXESVC pipe creation. In this undefended run, the service logon events (EID
4624/4627/4672) suggest PsExec progressed further than in the defended variant, but the
PSEXESVC named pipe and System EID 7045 are absent — either the System channel is not
collected or the service installation did not complete.

**No Sysmon events.** The Sysmon channel is absent. The defended variant contained Sysmon
EID 1 with the full `C:\Users\Public\Temp\ .\PsExec.exe -i -s cmd -accepteula` command
line, EID 17 (named pipe creation), EID 11 (file creates), and EID 7 (DLL loads).

## Assessment

This dataset is notably richer than the defended variant for one key difference: the service
logon events (EID 4624, 4627, 4672) appear here but not in the defended dataset. The presence
of Logon Type 5 (Service) events for SYSTEM originating from `services.exe` indicates that
PsExec, running from `C:\Users\Public\Temp\`, progressed far enough to cause the Windows SCM
to create a service logon session — a downstream consequence of PsExec beginning its service
installation sequence. Defender was not present to block this.

The TaskScheduler events for `OneSettings\RefreshCache` are genuine background OS noise that
happened to fall within the collection window. Their presence demonstrates how real datasets
include concurrent OS activity alongside attack telemetry.

## Detection Opportunities Present in This Data

**Security EID 4688 — `powershell.exe & {cd C:\Users\Public\Temp\`:** The combination of
a PowerShell `cd` to `C:\Users\Public\Temp\` followed by a PsExec invocation is a staging
directory indicator. `C:\Users\Public\` is world-writable and commonly used for tool staging.

**Security EID 4624 Logon Type 5 following PowerShell PsExec invocation:** A service
logon event (Logon Type 5 from `services.exe`) appearing shortly after a `powershell.exe`
process containing a PsExec command creates a correlation chain indicating PsExec progressed
to service installation. This sequence — PowerShell staging `→` Logon Type 5 — is
detectable as a multi-event pattern.

**Security EID 4672 — `SeDebugPrivilege` + `SeTcbPrivilege` for service logon:** The special
privilege set assigned in EID 4672 for the SYSTEM service logon includes `SeDebugPrivilege`
and `SeTcbPrivilege`, which are markers of a high-privilege service context. Correlating
this EID 4672 with the preceding EID 4688 for PsExec makes the causal chain explicit.

**TaskScheduler and Application channel events as OS noise baseline:** The OneSettings and
downlevel migration events demonstrate that real datasets contain concurrent background
activity. Detection logic must be robust to OS background activity occurring within the
same time window as adversarial actions.
