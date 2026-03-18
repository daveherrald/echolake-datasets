# T1012-6: Query Registry — Inspect SystemStartOptions Value in Registry

## Technique Context

T1012 Query Registry is a fundamental discovery technique where attackers query the Windows Registry to gather information about the system configuration, installed software, security settings, and other valuable reconnaissance data. The SystemStartOptions registry value specifically contains boot configuration data that reveals system startup parameters, which can provide insights into security configurations, debugging settings, and boot modes.

The detection community focuses on monitoring registry queries to sensitive keys, particularly those containing system configuration data, security settings, or persistence mechanisms. Common detection approaches include monitoring process command lines for registry utilities (reg.exe, PowerShell registry cmdlets), tracking Registry API calls, and identifying patterns of multiple registry queries that indicate systematic enumeration.

## What This Dataset Contains

This dataset captures a PowerShell-initiated registry query operation with the following key components:

**Primary Registry Query Chain:**
- Security 4688 shows PowerShell spawning cmd.exe: `"cmd.exe" /c reg.exe query HKLM\SYSTEM\CurrentControlSet\Control /v SystemStartOptions`
- Security 4688 shows cmd.exe spawning reg.exe: `reg.exe query HKLM\SYSTEM\CurrentControlSet\Control /v SystemStartOptions`
- Sysmon 1 events capture both process creations with full command lines

**Process Activity:**
- Multiple PowerShell processes (PIDs 6964, 7016, 7392) with extensive .NET runtime loading
- Sysmon EID 10 process access events showing PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF)
- Security 4703 token privilege adjustment showing PowerShell gaining extensive system privileges

**Supporting Reconnaissance:**
- whoami.exe execution for user context discovery (T1033)
- PowerShell script block logging showing only test framework boilerplate (Set-ExecutionPolicy Bypass)

## What This Dataset Does Not Contain

The dataset does not contain direct registry access telemetry from Sysmon EID 12/13/14 events, as these were likely filtered by the sysmon-modular configuration. The actual registry read operation and its results are not captured in the telemetry, only the process execution of reg.exe. No network activity or file system modifications related to the registry query are present. The PowerShell channel lacks the actual registry query commands, containing only execution policy changes and error handling boilerplate.

## Assessment

This dataset provides excellent coverage for detecting T1012 through process-based monitoring. The combination of Security 4688 command-line logging and Sysmon 1 process creation events captures the complete process chain from PowerShell through cmd.exe to reg.exe. The specific targeting of the SystemStartOptions registry value is clearly visible in the command lines. However, the lack of registry access events (EID 12/13/14) means defenders cannot see the actual registry keys accessed or values retrieved, limiting post-execution analysis capabilities.

## Detection Opportunities Present in This Data

1. **Registry Utility Process Execution** - Monitor Security 4688 and Sysmon 1 for reg.exe execution with sensitive registry paths like `HKLM\SYSTEM\CurrentControlSet\Control`

2. **PowerShell-to-Registry Tool Chain** - Detect PowerShell spawning cmd.exe which then spawns reg.exe, indicating scripted registry enumeration

3. **SystemStartOptions Query Detection** - Alert on specific queries to `SystemStartOptions` registry value as this reveals boot configuration details

4. **Process Access Pattern** - Monitor Sysmon 10 events showing PowerShell accessing child processes with full rights (0x1FFFFF) during registry operations

5. **Privilege Escalation Context** - Correlate Security 4703 token privilege adjustments with subsequent registry queries to identify elevated reconnaissance

6. **Command Line Pattern Matching** - Detect reg.exe command lines containing discovery-focused registry queries, particularly system configuration keys

7. **Cross-Process Correlation** - Link whoami.exe execution with registry queries to identify comprehensive system reconnaissance patterns
