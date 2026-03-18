# T1569.002-5: Service Execution — Use RemCom to Execute a Command on a Remote Host

## Technique Context

MITRE ATT&CK T1569.002 (Service Execution) covers adversary use of the Windows Service
Control Manager to execute programs. RemCom is an open-source PsExec alternative that
implements the same service-based remote execution protocol over SMB but with a different
binary signature. Adversaries choose RemCom specifically because it is less detected than
PsExec by security tools that focus on the `PSEXESVC` service name or the Sysinternals
binary hash as indicators. Like PsExec, RemCom copies a service binary to the target,
creates and starts a service, and returns a remote shell.

This test runs RemCom against `localhost` using hardcoded `Administrator` credentials
(`/user:Administrator /pwd:P@ssw0rd1`), mirroring a lateral movement scenario where an
operator reuses captured credentials to move across an environment.

In the defended variant, Windows Defender blocked RemCom execution. The `cmd.exe` wrapper
exited with `0x1`. No service installation events, no service-side process creation, and
no named pipe artifacts appeared. Notably, the defended dataset included TaskScheduler
events from a coincidentally-timed Windows Update Orchestrator task — and those same
TaskScheduler events appear in neither this undefended dataset nor its channel list,
confirming they were incidental OS noise in the defended dataset.

## What This Dataset Contains

The dataset spans approximately 2 seconds (17:41:54–17:41:56 UTC) and contains 118 total
events across two channels.

**Security channel (11 events) — EIDs 4688, 4689, 4703:**

EID 4688 records capture the attack chain:

**Pre-flight `whoami.exe`:**
```
New Process Name: C:\Windows\System32\whoami.exe
Process Command Line: "C:\Windows\system32\whoami.exe"
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Exit Status: 0x0
```

**`cmd.exe` RemCom wrapper:**
```
New Process Name: C:\Windows\System32\cmd.exe
Process Command Line: "cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPay...
Exit Status: 0x1
```

The `ExternalPay...` prefix continues as `loads\remcom.exe`. The full command from the
defended Sysmon EID 1 is:
```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\remcom.exe" \\localhost
  /user:Administrator /pwd:P@ssw0rd1 cmd.exe
```

This exposes: the RemCom binary path (`ExternalPayloads\remcom.exe`), the target
(`\\localhost`), explicit credentials (`/user:Administrator /pwd:P@ssw0rd1`), and the
payload (`cmd.exe`). The `0x1` exit code from `cmd.exe` indicates RemCom returned an
error — consistent with the localhost SMB execution environment not fully supporting
the RemCom protocol in this test configuration.

**Post-execution `whoami.exe`:**
```
Process Command Line: "C:\Windows\system32\whoami.exe"
Exit Status: 0x0
```

**Cleanup `cmd.exe`:**
```
Process Command Line: "cmd.exe" /c
Exit Status: 0x0
```

EID 4703 records SYSTEM token rights adjustment enabling elevated privileges for the
orchestrating `powershell.exe`, including `SeAssignPrimaryTokenPrivilege`,
`SeLoadDriverPrivilege`, `SeSecurityPrivilege`.

**PowerShell channel (107 events) — EIDs 4104, 4103:**

The 104 EID 4104 events are ART test framework boilerplate. EID 4103 records `Set-ExecutionPolicy
Bypass` and `Write-Host "DONE"`. The RemCom invocation runs via `cmd.exe /c` and does not
generate 4104 script block records beyond the outer test framework wrapper.

## What This Dataset Does Not Contain

**No System log events.** The System channel is not collected in this dataset. If RemCom
successfully installed a service, EID 7045 would appear in the System log. The absence of
System events means RemCom service installation cannot be confirmed or denied from this
dataset alone.

**No Sysmon events.** The defended variant included Sysmon EID 1 with the full RemCom
command line (including credentials), EID 13 for a registry write by `svchost.exe`,
EID 10 for process access, EID 17 for named pipe creation. None of those are present here.
The Security channel's truncated EID 4688 command line is the only evidence of RemCom.

**No `remcom.exe` process creation event.** Security EID 4688 captures `cmd.exe` as
the wrapper but not `remcom.exe` as its child. The audit policy scope does not capture
RemCom's process creation directly.

**No TaskScheduler events.** The defended dataset included four TaskScheduler events from
the Windows Update Orchestrator. Those events were incidental OS activity that happened
to fall within the defended test's collection window. In this undefended run they did not
occur, confirming they were unrelated to RemCom.

**No service artifacts for `RemCom_svc`.** RemCom installs a service with a name similar
to `RemCom_svc`. No EID 7045, no service registry key Sysmon events, and no Security
EID 4697 appear — either the service was not installed (due to the `0x1` failure) or the
relevant channels are not collected.

## Assessment

Like the PsExec test (T1569.002-2), this dataset shows RemCom invoked from a non-standard
path (`ExternalPayloads\`) with hardcoded credentials against localhost, but the tool
itself not fully succeeding. The `0x1` exit code from `cmd.exe` indicates RemCom returned
an error. The most valuable information in this dataset is the command line fragment
confirming RemCom was run from `C:\AtomicRedTeam\atomics\..\ExternalPayloads\remcom.exe`
with `-user:Administrator -pwd:P@ssw0rd1` style credential arguments.

Compared to the defended dataset, this undefended run contains marginally fewer Security
events (11 vs 19 in the defended dataset, which had service logon events EID 4624/4627/4672
from a service context logon). The absence of those logon events here suggests the
service-based remote execution did not reach the stage where Windows would create a service
logon session.

## Detection Opportunities Present in This Data

**Security EID 4688 — RemCom from `ExternalPayloads\`:** The path
`C:\AtomicRedTeam\atomics\..\ExternalPayloads\remcom.exe` is a non-standard location.
Any execution of `remcom.exe` from a user-writable path (`%APPDATA%`, `%TEMP%`,
`C:\Users\Public\`, staging directories) is an indicator of lateral movement tooling.

**Security EID 4688 — credential arguments in command line:** Remote execution tools
with explicit `/user:` and `/pwd:` arguments in the command line represent plaintext
credential exposure in logs. This applies equally to RemCom, PsExec, and similar tools.

**Absence of service logon events:** In the defended dataset, RemCom's attempted execution
triggered EID 4624 (Logon Type 5, Service) events — consistent with the Windows SCM
creating a service context. Their absence here (despite the same tool being run) suggests
RemCom failed before reaching the service installation stage. Monitoring for RemCom
execution that does NOT produce subsequent EID 7045 or EID 4624 events may indicate a
failed lateral movement attempt worth investigating.

**`cmd.exe` exit code `0x1` following RemCom invocation:** As with PsExec, non-zero exit
from the wrapper indicates either a block or a protocol failure. In environments where this
pattern repeats, an adversary may be probing connectivity before adjusting their approach.
