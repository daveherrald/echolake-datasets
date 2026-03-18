# T1529-2: System Shutdown/Reboot — Windows

## Technique Context

T1529 (System Shutdown/Reboot) covers adversary-initiated system restarts as an impact technique. A forced restart disrupts operations, terminates running processes (including monitoring and response tools), and can be used to complete ransomware payload deployment, flush memory, trigger boot-time persistence, or simply deny service. On Windows, `shutdown.exe /r /t <seconds>` is the most direct and widely observed method. This technique appears frequently in ransomware precursors, destructive malware, and administrative abuse scenarios. The Windows Event Log records a restart initiation in System event ID 1074 (with the initiating process, username, and reason code) and confirms the subsequent restart via event IDs 6006 (Event Log service stopped) and 6005 (Event Log service started after boot). These three events form the canonical restart detection chain.

## What This Dataset Contains

This is the most forensically complete dataset in this collection for T1529. The system actually rebooted, and the dataset captures events spanning the shutdown initiation, the actual restart, and post-boot system initialization across seven channels.

**Shutdown initiation:** Sysmon event ID 1 records `cmd.exe` with `CommandLine: "cmd.exe" /c shutdown /r /t 1` (tagged `T1059.003`), spawned by `powershell.exe` from `C:\Windows\TEMP\`. Security event ID 4688 captures both the `cmd.exe` and the resulting `shutdown.exe` with `Process Command Line: shutdown /r /t 1`, parent `cmd.exe`. The process chain is `powershell.exe → cmd.exe → shutdown.exe`.

**System event ID 1074:** The System channel records:
```
The process C:\Windows\system32\shutdown.exe (ACME-WS02) has initiated the restart of
computer ACME-WS02 on behalf of user NT AUTHORITY\SYSTEM for the following reason:
No title for this reason could be found
Reason Code: 0x800000ff
Shutdown Type: restart
```
This is the definitive indicator: it names the initiating process (`shutdown.exe`), the account (`SYSTEM`), and the reason code `0x800000ff` (which corresponds to an unspecified/programmatic shutdown rather than a user-initiated or planned maintenance restart).

**Restart confirmation:** System event ID 6006 (`The Event log service was stopped`) and ID 6005 (`The Event log service was started`) bracket the reboot. System event ID 6009 records the OS version string at startup, confirming the system came back online.

**Post-boot activity:** The Sysmon channel contains 1,203 events spanning the shutdown and subsequent boot, capturing dozens of `svchost.exe` process creates (tagged T1083) and services starting, plus `wevtutil.exe` runs for Defender manifest reinstallation (tagged T1070.001 by sysmon-modular). Sysmon event ID 255 records driver queue overflow errors during the high-activity boot window — `RegistryEvent`, `ImageLoad`, `FileCreate`, and `ProcessCreate` events were dropped. Security event IDs 1100, 4624, 4672, 4826, 6417 record the audit log shutdown, logon sessions, BCD load, and FIPS self-test from the post-boot authentication sequence.

The WMI channel records the SCM Event Log Filter subscription binding (event IDs 5859, 5860, 5861) that fires at startup. The Task Scheduler channel captures 59 events covering task engine startup, task executions, and completions during early boot.

## What This Dataset Does Not Contain

Security event ID 4688 for `shutdown.exe` is present but the command line field shows `shutdown /r /t 1` without the explicit path — this is because `shutdown.exe` was resolved via PATH from within `cmd.exe`. The full path `C:\Windows\System32\shutdown.exe` appears in the System 1074 event rather than the Security 4688 New Process Name field (which shows the unqualified process name from the command line).

No PowerShell script block (4104) contains a shutdown-related command. The test framework executed the test via `cmd.exe` rather than a PowerShell cmdlet, so no `Stop-Computer` or `Restart-Computer` event appears in the PowerShell channel. The 48 PowerShell events are test framework boilerplate only.

Sysmon event ID 255 confirms that events were dropped from the driver queue during the boot burst — specifically RegistryEvent, ImageLoad, FileCreate, and at least one ProcessCreate. The post-boot Sysmon coverage is incomplete.

## Assessment

This is a high-quality dataset for T1529 detection engineering. It provides the complete three-event canonical restart chain (1074 → 6006 → 6005) in the System channel, the process chain in Security 4688 and Sysmon event ID 1, and rich post-boot context. System event ID 1074 with reason code `0x800000ff` is particularly useful — this code indicates a programmatic, unscheduled restart that differs from the reason codes used by Windows Update or human-initiated restarts (which include descriptive reason strings). The dataset also demonstrates Sysmon queue overflow behavior under high event volume during boot, which is relevant for detection teams designing collection pipelines. A useful addition would be capturing Security 4688 for `shutdown.exe` with a fully-qualified path and preserving the System 41 (unexpected shutdown) event if applicable.

## Detection Opportunities Present in This Data

1. **System event ID 1074 with shutdown.exe as initiating process** — The explicit naming of `C:\Windows\system32\shutdown.exe` and `NT AUTHORITY\SYSTEM` with reason code `0x800000ff` in a single event is a high-fidelity detection trigger.
2. **Security 4688 for shutdown.exe with /r or /s flag** — `shutdown /r /t 1` appearing in the command line of a `shutdown.exe` process create outside of maintenance windows is directly detectable.
3. **Sysmon event ID 1 for cmd.exe with shutdown command** — `"cmd.exe" /c shutdown /r /t 1` is captured with the T1059.003 rule tag and parent `powershell.exe` confirmed via LogonGuid/ProcessGuid correlation.
4. **System 6006 immediately following System 1074 within a short timeframe** — The short interval between restart initiation and event log service stop (in this case, with `/t 1` — a 1-second countdown) is detectable as an anomalous rapid shutdown sequence.
5. **System 6005 (boot) without a corresponding planned maintenance window** — Post-restart event log service start on a workstation at an unexpected time, especially when preceded by a 1074 with reason code `0x800000ff`, indicates forced restart.
6. **Process chain powershell.exe → cmd.exe → shutdown.exe from TEMP directory** — The combination of CurrentDirectory `C:\Windows\TEMP\` and this process chain is strongly anomalous on a managed domain workstation.
7. **Security 1100 (audit log service shut down) correlated with 1074** — The audit logging service stopping in close temporal proximity to a System 1074 event creates a correlated multi-event detection opportunity.
