# T1218.001-1: Compiled HTML File — Compiled HTML Help Local Payload

## Technique Context

T1218.001 covers adversary abuse of the Windows HTML Help (`hh.exe`) binary and its `.chm` (Compiled HTML Help) file format. CHM files are structured archives containing HTML content, and the Windows HTML Help executable (`C:\Windows\hh.exe`) is a Microsoft-signed binary that interprets them. When a CHM file contains embedded scripting — VBScript or JavaScript — `hh.exe` will execute that script through the Internet Explorer scripting engine, enabling arbitrary code execution through a trusted binary.

This technique has been used by APT groups in spear-phishing campaigns, where victims are delivered a CHM file attachment that appears to be a legitimate help document. The local variant (test 1) involves opening a CHM file already present on disk, as opposed to loading from a remote URL.

In this test, `hh.exe` opens `C:\AtomicRedTeam\atomics\T1218.001\src\T1218.001.chm`, a pre-staged CHM file with embedded scripting. Execution runs as `NT AUTHORITY\SYSTEM` with Defender disabled on `ACME-WS06.acme.local`. This test generates the most diverse channel coverage in the T1218.001 series, with events appearing in Application, PowerShell, Security, Sysmon, and Task Scheduler logs.

## What This Dataset Contains

The dataset spans approximately 2 minutes (2026-03-17T16:44:07Z–16:46:10Z) — notably longer than other tests — and contains 181 total events across five channels: 121 PowerShell events (108 EID 4104, 13 EID 4103), 31 Security events (19 EID 4799, 6 EID 4688, 5 EID 4798, 1 EID 4702), 25 Sysmon events (12 EID 7, 5 EID 10, 5 EID 1, 2 EID 11, 1 EID 17), 4 Application events (2 EID 15, 1 EID 16394, 1 EID 16384), and 1 Task Scheduler event (EID 140).

Two Sysmon EID 1 events are central to this dataset. The first captures `cmd.exe` with the command line `"cmd.exe" /c hh.exe "C:\AtomicRedTeam\atomics\T1218.001\src\T1218.001.chm"` (tagged T1059.003, Windows Command Shell). The second captures `hh.exe` itself: `hh.exe "C:\AtomicRedTeam\atomics\T1218.001\src\T1218.001.chm"` — tagged directly as `technique_id=T1218.001,technique_name=Compiled HTML File`. The parent of `hh.exe` is the cmd.exe process, completing the chain: test framework PowerShell → cmd.exe → hh.exe → CHM scripting payload.

The Security channel is the most distinctive feature of this dataset compared to others in the T1218 series. The 19 EID 4799 events record security-enabled local group membership enumeration against multiple groups including Administrators (S-1-5-32-544), Backup Operators (S-1-5-32-551), Cryptographic Operators (S-1-5-32-569), Users (S-1-5-32-545), and others — 12 distinct built-in groups in total. The 5 EID 4798 events record local user group membership enumeration against specific accounts: Administrator, DefaultAccount, Guest, mm11711 (the local user account), and WDAGUtilityAccount. The process generating these enumeration events has PID 0x15f4 (5620), which the Process Name field truncates to `C:\Program Files\Cri...` — consistent with the Cribl Edge agent performing routine telemetry collection rather than the CHM payload.

The 1 EID 4702 event records a scheduled task being modified: `\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask` updated by `ACME\ACME-WS06$`. This matches the Task Scheduler EID 140 event recording the same task update. These are Windows license management background activities that happened to occur during the test window.

The Application channel's EID 16394 "Offline downlevel migration succeeded" and EID 16384 "Successfully scheduled Software Protection service for re-start" events are Windows licensing system activity, not attributable to the CHM payload.

Compared to the defended dataset (sysmon: 47, security: 32, powershell: 32, system: 1, taskscheduler: 7), this undefended run shows fewer Sysmon events (25 vs. 47) but has a larger PowerShell channel (121 vs. 32). The Security channel is somewhat smaller (31 vs. 32). The defended run's larger Sysmon count and additional system/taskscheduler channels reflect Defender and remediation activity.

## What This Dataset Does Not Contain

The scripting content embedded in the CHM file — the JavaScript or VBScript that executes when hh.exe opens the file — does not appear in the PowerShell script block log, because the script runs through the Internet Explorer scripting engine rather than PowerShell's engine. Any processes spawned by the CHM's embedded script are not present in the Sysmon EID 1 samples.

No network connection events are present. CHM-based attacks can include scripts that make outbound connections, but this local-payload variant does not generate observable network activity.

No Sysmon EID 13 registry modification events are present despite the Windows licensing system activity observed in the Security and Task Scheduler channels.

## Assessment

This dataset provides both the cmd.exe invocation and the `hh.exe` process creation as Sysmon EID 1 events — a complete process chain up to the CHM execution. The 2-minute window duration, combined with the license-management background activity in the Security and Application channels, illustrates that longer-running tests accumulate unrelated OS noise alongside technique-relevant events.

The Security channel's group and user membership enumeration events (4799, 4798) are an important calibration artifact: these events originate from the Cribl Edge agent performing telemetry collection, not from the CHM payload. Analysts working with this dataset should recognize that local group enumeration events are routine infrastructure activity in this environment and should not be attributed to the technique without additional process context.

The 13 PowerShell EID 4103 events (more than in most T1218 tests) reflect the more complex test framework cleanup sequence for this test, including the `Invoke-AtomicTest T1218.001 -TestNumbers 1 -Cleanup` call.

## Detection Opportunities Present in This Data

**Sysmon EID 1 — hh.exe with an explicit CHM file path:** The process creation event for `C:\Windows\hh.exe` appearing as a child of `cmd.exe` (which is itself a child of PowerShell running as SYSTEM) is the primary detection indicator. In normal user-facing scenarios, `hh.exe` is launched by the user double-clicking a CHM file or from within an application's help system, not from a SYSTEM-context scripted command line.

**cmd.exe intermediary invoking hh.exe:** The pattern `cmd.exe /c hh.exe <path>` is not how legitimate help file access occurs. Windows associates CHM files with hh.exe through the shell and opens them directly; wrapping the invocation in cmd.exe with an explicit path is a scripting artifact.

**hh.exe with a CHM file from a non-standard path:** The path `C:\AtomicRedTeam\atomics\T1218.001\src\T1218.001.chm` is test-specific, but the pattern — hh.exe opening a CHM file from a path other than `%SystemRoot%\Help\`, a software vendor's help directory, or a trusted application path — is the meaningful signal. CHM files delivered as email attachments or downloaded files would reside in user profile directories or temp locations.

**Security EID 4799/4798 — local group/user enumeration from non-interactive process:** While the enumeration events in this dataset originate from the Cribl Edge agent, the same event types would be generated by malicious CHM payloads performing host reconnaissance. The combination of hh.exe execution followed by local group enumeration from any process is worth correlating.

**Two-minute execution window:** The extended duration of this test (relative to other T1218 tests that complete in 4–9 seconds) may reflect the CHM payload performing actions that take time to complete. Anomalously long hh.exe process lifetimes compared to normal help file browsing are worth tracking.
