# T1529-12: System Shutdown/Reboot — Logoff System (Windows)

## Technique Context

T1529 (System Shutdown/Reboot) covers adversary use of shutdown, restart, or logoff commands to disrupt availability, force users off systems, or clear active sessions. The logoff variant — `shutdown /l` — is of particular interest in scenarios where an adversary wants to terminate an active user's session: clearing an analyst's remote desktop connection during an incident response, forcing credential re-entry to capture credentials through a follow-on attack, or disrupting a user who might observe suspicious activity on their workstation. In coordinated intrusions, mass logoffs across many systems can delay or prevent user-driven detection.

The defended variant of this test (75 Sysmon, 32 Security, 34 PowerShell, 2 Application, 1 TaskScheduler) captured a richer set of events including EID 4689 process exit records showing `shutdown.exe` exiting with status `0x1` — confirming the logoff failed because there was no active interactive user session when the command ran from SYSTEM in session 0. This undefended dataset tells a consistent story.

## What This Dataset Contains

The dataset spans 3 seconds (2026-03-17 17:06:38–17:06:41 UTC) on ACME-WS06 running as NT AUTHORITY\SYSTEM. It contains 131 events across three channels: 107 PowerShell, 19 Sysmon, and 5 Security. The significantly shorter collection window (3 vs. ~30 seconds in the defended run) explains the lower total event count.

**Security (5 events, EID 4688):** Five process creation events document the complete execution chain:

1. `"C:\Windows\system32\whoami.exe"` — test framework pre-flight (creator: `powershell.exe`)
2. `"cmd.exe" /c shutdown /l` — the technique command, spawned by `powershell.exe`
3. `shutdown  /l` — `shutdown.exe` created by `cmd.exe`
4. `"C:\Windows\system32\whoami.exe"` — post-execution test framework check
5. `"cmd.exe" /c` — cleanup invocation

The full execution chain is visible: `powershell.exe (PID 0x430c) → cmd.exe (PID 0x4624) → shutdown.exe (PID 0x3dd8)`. All processes run as NT AUTHORITY\SYSTEM with `TokenElevationTypeDefault (1)` and `Mandatory Label: S-1-16-16384` (System integrity). Note: the Security channel in this shorter collection window does not include EID 4689 (process exit) events that would confirm whether the logoff succeeded or failed — those were present in the defended variant's 32-event Security log.

**Sysmon (19 events, EIDs 1, 7, 10, 17):** Sysmon EID 1 captures process creations for the technique-relevant chain. `cmd.exe` is tagged `RuleName: technique_id=T1059.003,technique_name=Windows Command Shell` with command line `"cmd.exe" /c shutdown /l`. A second EID 1 captures `shutdown.exe` with command line `shutdown  /l` and parent `cmd.exe`. The two `whoami.exe` invocations are tagged `T1033`. EID 7 records 9 DLL load events. EID 10 fires four times (ProcessAccess, `T1055.001`). EID 17 records one named pipe create. No EID 13 (RegistrySet) events are present in this collection window — the `rdyboost` registry writes seen in the defended variant were artifacts of the longer collection window overlapping with ReadyBoot activity, not caused by the technique.

**PowerShell (107 events, EIDs 4103, 4104):** All test framework boilerplate: EID 4103 records `Set-ExecutionPolicy Bypass` and `Write-Host "DONE"`. The 104 EID 4104 entries are internal formatter stubs.

## What This Dataset Does Not Contain

- **No EID 4689 (process exit).** The defended variant captured `shutdown.exe` and `cmd.exe` exiting with status `0x1`, confirming the logoff command failed when invoked from session 0 without an active user. This undefended dataset's 3-second collection window did not capture those exit records, so the success or failure of the command cannot be determined from this data alone.
- **No EID 4624/4627/4672 logon events.** The defended run's 32 Security events included multiple service logon entries from `svchost.exe` instances starting during the test window. None fell within the undefended run's tighter collection window.
- **No Application log events (EID 903, 16384).** The defended variant captured Software Protection Platform events triggered by the approaching logoff. These are absent in the 3-second undefended window.
- **No TaskScheduler events.** The defended run included one Task Scheduler event associated with the logoff path. Absent here.
- **No Defender-specific differences.** `shutdown.exe` and `cmd.exe` are standard system binaries; their execution generates no AMSI events and Defender does not produce additional telemetry around them. The defended and undefended profiles are behaviorally equivalent at the command-line level.

## Assessment

The most important context for this dataset is that `shutdown /l` invoked from `NT AUTHORITY\SYSTEM` in session 0 (no interactive desktop) will typically fail. The logoff command requires an active interactive logon session to target; running it from a headless SYSTEM service context returns error code 1. The defended variant confirmed this via EID 4689 exit codes. This undefended dataset does not directly confirm failure, but given the identical execution context (session 0, SYSTEM), the same outcome is expected.

This means the technique as tested here represents a command invocation that generates telemetry without achieving its stated objective. That is still valuable for detection purposes — the command line is present, the process chain is documented — but analysts using this dataset should understand they are seeing evidence of a logoff *attempt*, not a successful logoff.

The undefended dataset is smaller than the defended variant (131 vs. ~141 total events across defended sources) primarily due to the narrower collection window. The core technique evidence — Security EID 4688 recording `"cmd.exe" /c shutdown /l` and `shutdown  /l` — is present in both and is the primary detection target.

## Detection Opportunities Present in This Data

- **Security EID 4688 command line:** `"cmd.exe" /c shutdown /l` is the core indicator, spawned by `powershell.exe` as SYSTEM. The `/l` flag (logoff) distinguishes this from legitimate system shutdown (`/s`) or restart (`/r`). The process chain `powershell.exe → cmd.exe → shutdown.exe` in rapid succession from a SYSTEM context is anomalous for normal administrative activity.
- **Sysmon EID 1 with `T1059.003` tag:** `cmd.exe` is tagged with the Windows Command Shell technique ID, with the full `/c shutdown /l` command line. The Sysmon rule correctly identified this as a command shell invocation pattern of interest.
- **Timestamp compression:** All five Security EID 4688 events fall within a 3-second window (17:06:38–17:06:41). This execution velocity — five process creations in 3 seconds from a SYSTEM-context PowerShell — is characteristic of scripted execution rather than interactive system management.
- **`shutdown.exe` parent process:** In production environments, `shutdown.exe` is typically launched by interactive user sessions or by management software with known parent processes. `cmd.exe` spawned by `powershell.exe` running as SYSTEM is an anomalous parent chain for a logoff operation.
