# T1569.002-5: Service Execution — Use RemCom to execute a command on a remote host

## Technique Context

T1569.002 (Service Execution) test 5 covers RemCom, an open-source PsExec alternative that
implements the same service-based remote execution protocol over SMB but with a different
tool signature. RemCom is used by adversaries precisely because it is less detected than
PsExec by some security tools that focus on PSEXESVC as an indicator. Like PsExec, RemCom
copies a service binary to the target, creates and starts a service, and returns a remote
shell. This test runs RemCom against `localhost` using hardcoded `Administrator` credentials,
mirroring a real lateral-movement scenario where an operator reuses captured credentials to
spread across the environment.

## What This Dataset Contains

The dataset spans approximately 6 seconds (14:30:51–14:30:57 UTC) from ACME-WS02, and
includes four log sources — notably including TaskScheduler, which makes this dataset unique
among the T1569.002 tests.

**Sysmon Event 1 (Process Create)** captures:
- `whoami.exe` (ART pre-flight, tagged T1033)
- `cmd.exe` with: `"C:\AtomicRedTeam\atomics\..\ExternalPayloads\remcom.exe" \\localhost /user:Administrator /pwd:P@ssw0rd1 cmd.exe` (tagged T1059.003)

The command line shows: source path (`ExternalPayloads\remcom.exe`), target (`\\localhost`),
explicit credentials (`/user:Administrator /pwd:P@ssw0rd1`), and payload (`cmd.exe`).

**Sysmon Event 13 (Registry Value Set)** captures `svchost.exe` writing to:
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\UpdateOrchestrator\Schedule Work\Index`
This is Windows Update Orchestrator activity — a scheduled task that ran coincidentally during
the test window, not related to RemCom.

**Security Events 4624, 4627, 4672** record Logon Type 5 (Service) for `NT AUTHORITY\SYSTEM`
with group membership and special privilege assignment. These are service-context logon events
that occur during the RemCom execution attempt and represent the local SCM establishing a
service session.

**Security 4688/4689** record `whoami.exe`, `powershell.exe`, `cmd.exe`, and `conhost.exe`
lifecycle under SYSTEM.

**TaskScheduler Event 140** records four updates to
`\Microsoft\Windows\UpdateOrchestrator\Schedule Work` by both `S-1-5-18` (SYSTEM) and
`ACME\ACME-WS02$`. This is OS background activity that occurred during the test window
and is unrelated to RemCom.

## What This Dataset Does Not Contain (and Why)

**No remcom.exe process create in Sysmon.** Like PsExec.exe, `remcom.exe` does not match
the sysmon-modular include-mode ProcessCreate rules. It runs as a child of `cmd.exe`, which
is captured, but the tool itself is not directly logged by Sysmon 1.

**No service installation events.** RemCom installs a service (typically named `RemCom_svc`
or similar) on the target. No System Event 7045, no Sysmon Event 12/13 for a service registry
key, and no Security Event 4697 appear. The System log is not collected in this dataset, and
Sysmon service events for RemCom's service are absent — again consistent with Defender
blocking the execution before service installation completes.

**No remote command execution evidence.** No `cmd.exe` process appears as a child of a RemCom
service, and no exit code or output is logged. RemCom most likely failed to complete its
service installation on localhost due to Defender intervention.

**No network events for SMB.** No Sysmon Event 3 for port 445 from `remcom.exe` appears,
consistent with the tool being blocked before establishing a connection.

**Background noise from UpdateOrchestrator.** The TaskScheduler events (4x Event 140 for
`Schedule Work`) and related Sysmon Event 13 registry writes are Windows OS background
activity that happened to fall within the 6-second collection window. They are not related
to RemCom and illustrate how real datasets include ambient OS telemetry alongside
technique-specific events.

## Assessment

The clearest signal is in Sysmon Event 1: `cmd.exe` with RemCom's full command line including
`\\localhost`, `/user:Administrator`, and `/pwd:P@ssw0rd1`. The credential material in the
process command line is a critical finding in a real investigation — hardcoded admin passwords
in a process command line are visible to any process on the system with appropriate privileges,
as well as in SIEM logs.

The Security logon events (4624 Type 5, 4672, 4627) add context about the SYSTEM service
session established during the execution attempt. The TaskScheduler and registry events are
ambient OS noise, demonstrating that real-world telemetry windows contain background activity
even in short 6-second captures.

## Detection Opportunities Present in This Data

- **Sysmon Event 1 / Security 4688**: `remcom.exe` or any unknown executable with
  `\\<hostname>` `/user:` `/pwd:` parameter patterns in command line. Cleartext credentials
  in process command lines are a critical risk indicator regardless of the tool.

- **Sysmon Event 1**: `cmd.exe` child process where the command line contains
  `ExternalPayloads\` or other non-standard paths for remote execution tools.

- **Security 4688**: Full command line containing `remcom.exe \\` with credential flags;
  requires command-line auditing (`process_creation: success` + `command_line_logging: true`).

- **Security 4624 (Type 5) + 4672**: Service logon with special privilege assignment
  (`SeDebugPrivilege`, `SeImpersonatePrivilege`) in rapid succession can indicate a service
  being started as part of lateral movement tooling.

- **System 7045 (not in this dataset)**: Service installation with a RemCom-style service
  name and binary path on the target host would be the definitive remote execution indicator.

- **TaskScheduler Event 140**: Background UpdateOrchestrator events in this dataset illustrate
  that OS-generated noise should be baselined and filtered when building detection logic around
  scheduled task events.
