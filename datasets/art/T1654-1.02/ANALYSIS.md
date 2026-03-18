# T1654-1: Log Enumeration — Get-EventLog To Enumerate Windows Security Log

## Technique Context

T1654 (Log Enumeration) covers adversary attempts to read Windows event logs, typically to understand what monitoring is in place, locate evidence of their own prior actions, or gather information about user activity and system events. The PowerShell `Get-EventLog` cmdlet provides a straightforward way to read event log contents programmatically. Adversaries use log enumeration both for situational awareness and as a precursor to log tampering (T1070.001) — understanding what is logged before attempting to clear or modify it. `Get-EventLog` is a legacy PowerShell cmdlet that wraps the Win32_NTEventlogFile WMI class; on modern Windows 11 systems, `Get-WinEvent` is the preferred replacement, but `Get-EventLog` may still function for standard log sources.

## What This Dataset Contains

Three log channels are present: 34,503 Security events, 116 PowerShell events, and 2 Application events.

**Security log (34,503 events)**:
- **EID 4703** (34,488 events) — Token right adjustment events for `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` running as SYSTEM. Each event records `SeSecurityPrivilege` being disabled on the PowerShell process. The volume here — approximately 34,488 events — is far outside the expected range for a short test execution. `SeSecurityPrivilege` is required to read the Security log; a process that repeatedly acquires and releases this privilege while iterating over Security log entries generates a token adjustment event for each operation cycle. This event flood is a direct artifact of `Get-EventLog -LogName Security` reading the Security log: the PowerShell process is cycling `SeSecurityPrivilege` for each batch of records read, and with a populated Security log (the ACME-WS06 environment generates continuous Security events from other test runs), this produces tens of thousands of 4703 events.
- **EID 4689** (11 events) — Process exits for `powershell.exe` and associated processes.
- **EID 4688** (4 events) — Process creation for `whoami.exe` (identity checks) spawned from `powershell.exe`.

**PowerShell log (116 events)** — 111 EID 4104 script block events, 5 EID 4103 module pipeline events. The sample set contains `Set-ExecutionPolicy Bypass -Scope Process -Force` and `$ErrorActionPreference = 'Continue'`. The `Get-EventLog` call itself runs within the PowerShell process and does not produce a distinct script block separate from the test framework invocation.

**Application log (2 events)**:
- **EID 15** (2 events) — `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON`, present in multiple undefended test datasets, reflecting Defender state-reporting activity during the test window.

## What This Dataset Does Not Contain

The contents of the Security log as read by `Get-EventLog` — the actual enumerated event data — are not captured in any channel. The cmdlet reads log entries into memory within the PowerShell process and returns them to the caller; this operation generates no output to auditable event channels.

Sysmon events are absent. `Get-EventLog` operates entirely within the PowerShell process, spawning no child processes that would trigger Sysmon EID 1. The Sysmon include-mode ProcessCreate rules have no entry for `powershell.exe` itself, and no file writes, registry accesses, or network connections occur.

No registry access events are present. While `Get-EventLog` uses WMI internally, no WMI channel events appear — the WMI query is handled in-process without generating WMI operational log entries in this configuration.

## Assessment

The dominant feature of this dataset is the 34,488 EID 4703 flood. This is a direct, measurable consequence of the technique: reading the Security log as SYSTEM on a busy system generates massive token adjustment event volume. This makes T1654-1 one of the most distinctive datasets in the series from a volume perspective, even though individual events are not particularly informative.

The defended variant produced no events (empty dataset). This is a meaningful difference: with Defender active, the AMSI integration with PowerShell may have blocked or modified the `Get-EventLog` invocation, or the collection window captured no events from that test run. With defenses disabled, the technique executes cleanly and generates the 4703 flood described above. You can therefore treat this dataset as the authoritative representation of what T1654-1 looks like when it succeeds.

The EID 4703 volume is itself a detection opportunity — normal PowerShell processes do not cycle `SeSecurityPrivilege` tens of thousands of times in a short window. A threshold-based alert on EID 4703 volume per process ID over a short time window would fire reliably on this behavior.

For detection engineers building SIEM content for T1654, this dataset provides a realistic volume baseline: a single `Get-EventLog -LogName Security` invocation on a moderately busy Windows 11 workstation generates approximately 34,000 EID 4703 events in the time it takes to iterate through the log. This volume information helps set alert thresholds appropriately.

## Detection Opportunities Present in This Data

- **Security EID 4703: High volume of `SeSecurityPrivilege` disable events from `powershell.exe`** — Threshold on EID 4703 events where `ProcessName` is `powershell.exe` (or any process not expected to cycle Security privileges) and `DisabledPrivilegeList` contains `SeSecurityPrivilege`. A rate of more than ~100 such events per minute from a single process ID is a strong indicator of Security log enumeration. Alert threshold suggested: >500 EID 4703 events from a single `ProcessId` within any 60-second window.

- **EID 4104: Script block containing `Get-EventLog` + `-LogName Security`** — If PowerShell script block logging captures the `Get-EventLog -LogName Security` invocation (which it will, when the cmdlet is called from a non-obfuscated script), this is a high-fidelity detection. Alert on EID 4104 script blocks containing `Get-EventLog` with `-LogName Security` or `-LogName "Security"`.

- **EID 4104: Script block containing `Get-WinEvent` + Security log filter** — The modern equivalent of this technique uses `Get-WinEvent -LogName Security`. Alert on EID 4104 containing `Get-WinEvent` combined with `Security` as a log name or a `FilterHashtable` targeting the Security log.

- **Correlation: EID 4703 volume spike + EID 4688 PowerShell process creation** — Correlate a high-volume EID 4703 burst with a prior EID 4688 event creating the `powershell.exe` process responsible. The process ID from the 4703 events links back to the 4688 creation event, providing the command line and parent process context needed to triage the alert.

- **EID 4688: `whoami.exe` spawned by `powershell.exe` as SYSTEM** — While `whoami.exe` is a low-fidelity indicator alone, its appearance as a child of a SYSTEM-context `powershell.exe` immediately before or after a large EID 4703 burst provides a contextual signal that the PowerShell session is performing privileged reconnaissance activities.
