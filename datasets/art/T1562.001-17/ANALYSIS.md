# T1562.001-17: Disable or Modify Tools — Tamper with Windows Defender Command Prompt

## Technique Context

T1562.001 (Disable or Modify Tools) includes disabling Windows Defender's WinDefend service via command-line service control utilities. This test uses `sc.exe stop WinDefend` and `sc.exe config WinDefend start=disabled` — the Windows Service Control Manager — rather than PowerShell's `Set-MpPreference`. The command-line approach targets the service itself rather than individual Defender preference settings, making it a more blunt and complete disruption. Like test 16, this is a living-off-the-land technique using a built-in, signed Microsoft binary.

## What This Dataset Contains

The dataset captures 75 events across Sysmon, Security, and PowerShell logs collected during a 6-second window on 2026-03-14 at 14:50 UTC.

The Defender service disruption command is captured in Security EID 4688:

```
"cmd.exe" /c sc stop WinDefend & sc config WinDefend start=disabled & sc query WinDefend
```

Key observations from the data:

- **Security EID 4688**: `cmd.exe` with the full command chain: `sc stop WinDefend & sc config WinDefend start=disabled & sc query WinDefend`, spawned by `powershell.exe` as NT AUTHORITY\SYSTEM. The `sc query WinDefend` at the end is used by the ART test to verify the service state post-attempt.
- **Sysmon EID 1**: `whoami.exe` (T1033 rule) fires before the main command. Only one Sysmon EID 1 is captured for the sc.exe activity — the `cmd.exe` itself does not appear in Sysmon EID 1 because `cmd.exe` did not match the include-mode rules at this position in the execution chain. Note: only `whoami.exe` is captured in Sysmon EID 1 here, not `cmd.exe` or `sc.exe`.
- **Sysmon EID 8 (CreateRemoteThread)**: `powershell.exe` (PID 5484) creates a remote thread in an `<unknown process>` (PID 2936) at `StartAddress: 0x00007FF673B10570` with `StartModule: -` and `StartFunction: -`. This is the ART test framework output-capture mechanism (PowerShell using `System.Diagnostics.Process` to run the cmd.exe subprocess). The unknown process is the short-lived `cmd.exe` subprocess that has already exited by the time Sysmon resolves it.
- Sysmon EID 7 fires for the PowerShell DLL load chain.
- Sysmon EID 17 records the PowerShell named pipe creation.
- Sysmon EID 10 (ProcessAccess) from PowerShell to `whoami.exe` — ART output-capture artifact.
- **PowerShell EID 4104**: No Defender or sc.exe content. Only ART boilerplate error-handling scriptblocks. The sc.exe invocation runs in a cmd.exe subprocess and is not logged by PowerShell scriptblock logging.
- **PowerShell EID 4103**: Only `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` — ART test framework boilerplate.

A key observation: Windows Defender with tamper protection would block `sc stop WinDefend`. In this environment, Defender's tamper protection is not enabled (or the SYSTEM context bypasses it). The dataset does not contain evidence of whether the stop succeeded — there are no System log service state change events (EID 7034/7036) in the collected channels.

## What This Dataset Does Not Contain (and Why)

**No sc.exe process creation in Sysmon (EID 1).** The sysmon-modular include-mode ProcessCreate rules do not match `sc.exe` for the WinDefend stop pattern at this execution depth. Security EID 4688 covers this gap.

**No cmd.exe in Sysmon EID 1.** The `cmd.exe` spawned to run the sc.exe chain does not appear in Sysmon EID 1, unlike test 15 where `cmd.exe` was captured with RuleName T1059.003. This is a coverage inconsistency in the include-mode filtering, likely depending on the parent-child context and specific rule evaluation.

**No Windows Defender event log.** The Microsoft-Windows-Windows Defender/Operational channel is not collected, so EID 5001 (real-time protection disabled) or similar events are absent.

**No System service log events.** System EID 7034/7036 (service stopped/started) are not in the collected channels, so the outcome of `sc stop WinDefend` cannot be determined from this dataset alone.

**No confirmation of success.** Unlike test 15 where the service name did not exist, WinDefend exists on all Windows hosts, but tamper protection state would determine whether the stop succeeded.

## Assessment

This dataset captures a Defender service stop attempt with Security EID 4688 as the primary evidence source. The complete sc.exe command chain — stop, disable, query — is visible in the cmd.exe command line. Sysmon provides limited additional value here due to include-mode filtering not capturing cmd.exe or sc.exe directly in this context, though the EID 8 CreateRemoteThread from PowerShell adds a behavioral marker. The lack of System log service events means outcome cannot be determined within this dataset. The PowerShell logs contain no technique-relevant content because the sc.exe invocation occurs entirely within a cmd.exe subprocess outside of PowerShell's logging scope.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `cmd.exe` command line containing `sc stop WinDefend`, `sc config WinDefend start=disabled`, spawned from `powershell.exe` as SYSTEM.
- **Security EID 4688**: The presence of `sc query WinDefend` immediately after stop/disable is an ART test framework artifact but also appears in real attacker scripts that verify service state — the three-command chain is a characteristic pattern.
- **Sysmon EID 8 (CreateRemoteThread)**: PowerShell creating a remote thread in an unknown/exited process with an anonymous start address — indicates PowerShell is launching subprocesses in a way that triggers Sysmon's injection rule, which warrants investigation.
- **Sysmon EID 1**: `whoami.exe` as SYSTEM immediately before Defender-related activity indicates automated post-exploitation execution flow.
- **Service name monitoring**: Any `sc stop WinDefend`, `sc config WinDefend start=disabled`, or `net stop WinDefend` invocation should trigger high-priority alerting regardless of context.
- **Correlation with test 16**: When `Set-MpPreference` tampering (test 16) and `sc stop WinDefend` (test 17) both appear in a session, the combined evidence represents a systematic effort to disable Defender through multiple pathways.
