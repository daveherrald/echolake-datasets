# T1562.001-28: Disable or Modify Tools — Disable Defender Using NirSoft AdvancedRun

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) includes using third-party
utilities to stop the Windows Defender service. NirSoft AdvancedRun is a legitimate
administration utility that can launch processes with specific user contexts, including as
TrustedInstaller — a privilege level higher than SYSTEM. By running `sc.exe stop WinDefend`
via AdvancedRun with `/RunAs 8` (TrustedInstaller context), an adversary attempts to stop
the WinDefend service with a token that bypasses Defender's Tamper Protection, which only
protects against SYSTEM-level interference. This technique has been observed in ransomware
pre-staging phases and represents a more sophisticated bypass than direct service control.

## What This Dataset Contains

The dataset captures 19 Sysmon events, 10 Security events, 41 PowerShell events, and 3
Task Scheduler events spanning approximately 5 seconds on ACME-WS02 (Windows 11 Enterprise,
domain member of acme.local).

The attack payload is captured in Security 4688 as the child PowerShell command line:

```
"powershell.exe" & {Try {cmd /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdvancedRun.exe"
  /EXEFilename "$env:systemroot\System32\sc.exe"
  /WindowState 0
  /CommandLine "stop WinDefend"
  /StartDirectory ""
  /RunAs 8
  /Run} Catch{}
if(0){
  $CommandToRun = rmdir "$env:programdata\Microsoft\Windows Defender" -Recurse
  Try {cmd /c "...AdvancedRun.exe" /EXEFilename "...powershell.exe"
       /CommandLine "$CommandToRun" /RunAs 8 /Run} Catch{}
}}
```

The script structure is revealing: a `Try/Catch` wraps the AdvancedRun invocation to
suppress errors, and a second action (removing the Defender directory tree) is gated on
`if(0)` — permanently disabled in the test, indicating it is a cleanup-phase action
not executed by default.

**The child PowerShell process exited with status 0xC0000022** (ACCESS_DENIED). Defender
blocked the attempt. A Sysmon EID 8 (CreateRemoteThread) event is present with the
PowerShell process as the source and `<unknown process>` as the target — the same
Defender behavior monitoring signature observed in test -27. A Sysmon EID 13 is present
for a Task Scheduler cache entry unrelated to the attack (OS telemetry for the OneSettings
RefreshCache task). Task Scheduler events (EID 102, 140, 201) for the same unrelated
scheduled task are also present.

## What This Dataset Does Not Contain (and Why)

**No AdvancedRun.exe in Sysmon EID 1 or Security 4688.** The sysmon-modular include rules
do not match `AdvancedRun.exe` by name, and Security 4688 does not log AdvancedRun as a
separate process because the 0xC0000022 exit on the parent PowerShell means the command
was blocked before or during launch. The command structure routes through `cmd.exe` as an
intermediate, but no separate `cmd.exe` or `AdvancedRun.exe` process creation events appear
in the bundled data.

**No `sc.exe` process creation.** AdvancedRun was not able to spawn `sc.exe stop WinDefend`
under TrustedInstaller context — the Defender block prevented it. No service control events
appear.

**No WinDefend service stop events.** The service was not stopped. The exit code 0xC0000022
on the PowerShell process confirms Defender blocked the operation.

**No PowerShell 4104 script block for the attack payload.** The script block was not logged
by PowerShell Script Block Logging — consistent with AMSI or Defender blocking the script
execution before the block could be recorded. The 4104 events present are entirely the
internal error-handling closure boilerplate from the test framework wrapper.

**The second attack stage (rmdir Defender directory) was disabled.** The `if(0)` gate
prevents the directory removal action from executing. This is an ART test design decision
to avoid potentially unrecoverable host state changes.

## Assessment

The test executed and was blocked. Windows Defender's Tamper Protection prevented the
TrustedInstaller-context service stop attempt. The exit code 0xC0000022 and the Sysmon
EID 8 CreateRemoteThread with `<unknown process>` provide characteristic evidence of
Defender's active behavioral intervention. The absence of a PowerShell 4104 script block
for the attack payload is itself a detection signal — it suggests AMSI terminated the
execution before script block logging could fire.

## Detection Opportunities Present in This Data

- **Security 4688 command line containing `AdvancedRun.exe` with `/RunAs 8`**: The
  TrustedInstaller execution mode flag (`/RunAs 8`) combined with `AdvancedRun.exe` and
  `stop WinDefend` in the same command line is unambiguous. AdvancedRun has limited
  legitimate use in enterprise environments.

- **Exit code 0xC0000022 from PowerShell**: ACCESS_DENIED at the PowerShell process level
  (not just a child process) indicates Defender blocked the execution at the script level.
  Combined with the attack command in the 4688 event, this is a clear blocked-attempt
  indicator.

- **Sysmon EID 8 (CreateRemoteThread) with `<unknown process>` target**: This pattern
  recurs in both test -27 and -28. PowerShell creating a remote thread into an ephemeral
  process during a Defender service interaction is a consistent Defender behavior monitoring
  fingerprint. Correlating EID 8 events with this target pattern against nearby defense
  evasion activity is a productive detection strategy.

- **Task Scheduler noise**: The OneSettings RefreshCache task events (EID 102, 140, 201)
  are unrelated OS telemetry that coincidentally fired during the test window. They do not
  indicate attacker activity and should not be correlated with the defense evasion events.

- **Absence of 4104 script block**: The lack of a PowerShell script block log entry for
  the known-malicious command (visible in 4688) suggests AMSI intervention. Monitoring for
  this mismatch — process creation with suspicious content in the command line but no
  corresponding 4104 script block — can surface AMSI-blocked executions.
