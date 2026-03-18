# T1124-6: System Time Discovery — Discover System Time Zone via Registry

## Technique Context

T1124 System Time Discovery is a discovery technique where adversaries gather information about the system time and timezone configuration to understand their operational environment. Time zone information is particularly valuable for attackers planning persistence mechanisms, understanding business hours, or coordinating multi-stage attacks across different geographic regions. The detection community focuses on registry queries to time-related keys, command-line utilities accessing time information, and PowerShell cmdlets that retrieve system time data. This specific test demonstrates registry-based timezone discovery, which is a common approach used by both malware and legitimate administration tools.

## What This Dataset Contains

This dataset captures a PowerShell-driven registry query to discover the system timezone. The primary technique evidence appears in Security event 4688, showing the process chain: `powershell.exe` → `cmd.exe` → `reg.exe` with the command line `reg query "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v TimeZoneKeyName`. 

The complete process execution chain is visible across multiple log sources:
- Security 4688 events show process creation for `whoami.exe`, `cmd.exe`, and `reg.exe`
- Sysmon EID 1 events capture the same process creations with additional metadata including file hashes and parent process relationships
- PowerShell events contain only execution policy bypass boilerplate (`Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`)
- Sysmon EID 10 events show PowerShell accessing child processes with full access rights (0x1FFFFF)

The key technical indicator is the registry query targeting `HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation` with the specific value `TimeZoneKeyName`, which directly maps to T1124 behavior patterns.

## What This Dataset Does Not Contain

The dataset lacks the actual registry query results or output from the `reg.exe` command. While we see the command execution, there's no captured stdout showing the timezone value that would have been returned. The PowerShell channel contains no script block logging of the actual commands that initiated this discovery activity—only the execution policy changes. Additionally, there are no registry access events (Sysmon EID 12/13) which would show the specific registry read operations, likely due to the sysmon-modular configuration not monitoring all registry access patterns.

## Assessment

This dataset provides solid evidence for detecting T1124 registry-based timezone discovery. The command line evidence in both Security 4688 and Sysmon EID 1 events is unambiguous and directly actionable for detection rules. The parent-child process relationships are clearly captured, enabling process chain analysis. The Sysmon process access events add additional context about PowerShell's interaction with spawned processes. However, the lack of actual registry access events and command output limits the dataset's utility for understanding the full attack lifecycle or building more sophisticated behavioral detections.

## Detection Opportunities Present in This Data

1. **Registry Query Command Line Detection** - Monitor Security 4688 or Sysmon EID 1 for command lines containing `reg query` with `TimeZoneInformation` and `TimeZoneKeyName` parameters

2. **Suspicious Process Chain Analysis** - Detect PowerShell spawning cmd.exe which then spawns reg.exe, particularly when querying system configuration registry keys

3. **PowerShell Child Process Monitoring** - Alert on PowerShell processes creating registry query utilities (reg.exe) as child processes

4. **System Discovery Activity Correlation** - Combine timezone registry queries with other discovery commands (like whoami.exe) executed in close temporal proximity

5. **Process Access Pattern Detection** - Monitor Sysmon EID 10 events where PowerShell processes access registry utilities with full access rights (0x1FFFFF)

6. **LOLBin Registry Abuse** - Detect legitimate Windows utilities (reg.exe) being used for system reconnaissance activities based on specific registry paths queried
