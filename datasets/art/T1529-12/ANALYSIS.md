# T1529-12: System Shutdown/Reboot — Windows

## Technique Context

T1529 (System Shutdown/Reboot) covers adversary use of shutdown, restart, or logoff commands
to disrupt availability, force users off systems, or complete a destructive operation. The
logoff variant (`shutdown /l`) is sometimes used to clear interactive sessions, force
credential re-entry, or interrupt an active user's work. In the context of a ransomware or
destructive attack, coordinated logoffs across many systems can prevent users from responding
to or observing an attack in progress.

## What This Dataset Contains

The test invokes `shutdown /l` via cmd.exe, executed as NT AUTHORITY\SYSTEM:

```
cmd.exe /c shutdown /l
```

**Sysmon (75 events, EIDs 1, 7, 10, 11, 13, 17):**
Three EID 1 ProcessCreate events are present. An `svchost.exe` spawned by `services.exe`
is captured (RuleName `T1083`) — a background OS event coinciding with the test window. The
ART test framework `whoami.exe` (RuleName `T1033`) is captured. The primary attack action is
recorded: `cmd.exe` created by the test framework PowerShell with command line `"cmd.exe" /c shutdown /l` (RuleName `T1059.003/Windows Command Shell`). A subsequent EID 1 in the security
log shows `shutdown.exe` created by `cmd.exe`.

Three EID 13 (Registry value set) events record writes to
`HKLM\System\CurrentControlSet\Services\rdyboost\` (ReadyBoot volume parameters) by
`svchost.exe` — a background storage system activity triggered by the approaching logoff,
not directly caused by the test script.

The remaining 69 Sysmon events are EID 7 ImageLoad entries for multiple PowerShell processes
(three test framework invocations are visible), EID 17 named pipe creates, EID 11 file creates in
the SYSTEM profile temp path, and EID 10 process access events.

**Security (32 events, EIDs 4624, 4627, 4672, 4688, 4689, 4703):**
This is the most informative channel for this test. 4688 records `svchost.exe` (services),
`whoami.exe`, `cmd.exe` with `shutdown /l`, and `shutdown.exe` with its exact arguments.
The key finding in 4689 (process exit): **`shutdown.exe` exits with status 0x1**, and the
parent `cmd.exe` also exits with 0x1 — indicating the logoff command **failed**. The
`shutdown /l` verb requires an active user session; when invoked from a SYSTEM service
context (session 0) with no interactive logon to log off, it returns an error.

Four 4624/4627/4672 event triples record SYSTEM service logon events (Logon Type 5) that
were triggered by service starts during the test window. These are normal background activity
from the OS spin-up of new svchost instances (BDESVC, wsappx, ClipSVC were identified in the
process creation records).

**PowerShell (34 events, EIDs 4103, 4104):**
Two 4103 events record `Set-ExecutionPolicy Bypass -Scope Process` (ART test framework boilerplate).
The remaining events are 4104 script block entries for PowerShell's internal formatter stubs.

**Application (2 events, EIDs 903, 16384):**
EID 903 records "The Software Protection service has stopped." EID 16384 records that the
Software Protection service (SPPSVC / Windows licensing) rescheduled itself for restart at
2026-03-15T02:21:30Z with reason "TBL". These are normal background activity triggered by
the logoff attempt and associated service lifecycle events.

**TaskScheduler (1 event, EID 140):**
The Task Scheduler updated the `\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask`
task, corresponding to the SPPSVC rescheduling. This is a direct consequence of the licensing
service restart triggered by the attempted session termination.

## What This Dataset Does Not Contain (and Why)

**A successful logoff:** The `shutdown.exe` exit code is 0x1 — the logoff did not succeed.
The test ran under NT AUTHORITY\SYSTEM in a non-interactive session (session 0); `shutdown /l`
operates on the calling user's interactive session, which does not exist for a service account
running from a QEMU guest agent. No session termination events (e.g., 4647) are present.

**User-visible impact:** Because the logoff failed, no interactive user session was
terminated. There are no 4634 (logoff) events, no session-end events, and no evidence that
any signed-in user was affected.

**Defender interference:** Windows Defender did not block this test. `shutdown.exe` is a
legitimate Windows binary; the failure was a semantic error (no interactive session to log
off), not a security block.

## Assessment

The test produced rich process creation and exit telemetry, but the core action — logging off
a user — did not succeed due to execution context. This is an important data quality note:
the telemetry captures an **attempt** at T1529, not a successful execution. The Security
channel exit code (0x1 for both `shutdown.exe` and `cmd.exe`) is the evidence of failure.
Detectors working from this data should treat it as the execution attempt observable, not
the impact observable.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `cmd.exe /c shutdown /l` spawned by a non-interactive
  SYSTEM PowerShell process (session 0, no script path) is anomalous. Legitimate
  administrators and scripts rarely invoke `shutdown /l` from a SYSTEM service context.
- **Security EID 4689:** `shutdown.exe` exit status 0x1 is a meaningful signal. Detection
  rules that pair process creation (4688) with process termination (4689) and flag non-zero
  exit codes from `shutdown.exe` can identify both successful and failed logoff/shutdown
  attempts.
- **Process chain:** `powershell.exe` (SYSTEM, session 0) → `cmd.exe` → `shutdown.exe /l`
  is a specific three-hop ancestry pattern with no plausible benign explanation when the
  initiating PowerShell has no associated script path.
- **TaskScheduler EID 140 + Application 903/16384:** The SPPSVC restart scheduling
  coincident with a `shutdown /l` attempt is a corroborating artifact. In a real attack
  scenario, these secondary events would help bound the time window and associate the
  logoff attempt with downstream system changes.
- **Cluster of service logon events (4624 Logon Type 5):** Multiple new service sessions
  starting in the same window as a shutdown attempt reflects OS-level service churn that
  can help corroborate a disruption attempt.
