# T1069.001-6: Local Groups — WMIObject Group Discovery

## Technique Context

T1069.001 Local Groups is a Discovery technique where attackers enumerate local groups on Windows systems to understand privileges and potential privilege escalation paths. This technique is fundamental to post-exploitation activities as it helps attackers map out group memberships, identify high-privilege accounts, and plan lateral movement or privilege escalation strategies.

Attackers commonly use this technique through various methods including `net localgroup`, WMI queries, PowerShell cmdlets, and direct Win32 API calls. The detection community focuses on monitoring command-line patterns, PowerShell activity involving group enumeration cmdlets, WMI queries for group objects, and API calls to functions like `NetLocalGroupEnum`.

This specific test uses PowerShell's `Get-WmiObject Win32_Group` cmdlet, which queries WMI to retrieve group information—a method that provides comprehensive group details and is commonly used by both legitimate administrators and attackers.

## What This Dataset Contains

This dataset captures a PowerShell-based WMI group discovery execution with clear telemetry across multiple channels:

**Process Chain**: The Security channel shows the process creation for the main discovery command: `"powershell.exe" & {Get-WMIObject Win32_Group}` (PID 29304) spawned from a parent PowerShell process.

**PowerShell Evidence**: The PowerShell channel contains the key technique evidence in EID 4103 CommandInvocation events showing `Get-WmiObject` with `ParameterBinding` for `name="Class"; value="Win32_Group"`. PowerShell script blocks in EID 4104 events capture `& {Get-WMIObject Win32_Group}` and `{Get-WMIObject Win32_Group}`.

**WMI Activity**: Sysmon EID 7 events show the loading of WMI-related DLLs including `wmiutils.dll` with RuleName matching `technique_id=T1047,technique_name=Windows Management Instrumentation`, indicating WMI subsystem activation.

**Supporting Process Activity**: Sysmon EID 1 events capture both the whoami.exe execution (likely for initial context gathering) and the main PowerShell process with the full command line containing the WMI query.

## What This Dataset Does Not Contain

The dataset lacks some telemetry that could provide additional context for this technique:

**WMI Event Logs**: The dataset doesn't include Microsoft-Windows-WMI-Activity/Operational logs that would show the actual WMI query execution and results, which are valuable for detecting WMI-based discovery activities.

**Network Activity**: No network-related events are captured, though WMI queries to local groups typically don't generate network traffic unless targeting remote systems.

**Process Access Events**: While Sysmon EID 10 events show process access to whoami.exe and the child PowerShell process, there are no events specifically related to WMI provider access or group enumeration APIs.

## Assessment

This dataset provides good coverage for detecting PowerShell-based WMI group discovery activities. The combination of Security 4688 events with command-line logging, PowerShell operational logs with cmdlet invocation details, and Sysmon process creation events offers multiple detection opportunities. The PowerShell telemetry is particularly strong, capturing both the command invocation and script block content.

The main limitation is the absence of WMI-specific event logs, but the existing telemetry sources provide sufficient evidence for reliable detection. The process chain visibility and PowerShell command-line arguments make this technique quite detectable with the current instrumentation.

## Detection Opportunities Present in This Data

1. **PowerShell WMI Group Query Detection** - Monitor PowerShell EID 4103 CommandInvocation events for `Get-WmiObject` cmdlet with `Win32_Group` class parameter binding

2. **Command-Line Group Discovery Pattern** - Alert on Security EID 4688 process creation events with command lines containing `Get-WMIObject Win32_Group` or similar WMI group query patterns

3. **PowerShell Script Block Group Enumeration** - Detect PowerShell EID 4104 script block events containing WMI group discovery patterns like `Win32_Group`

4. **WMI Utility DLL Loading** - Monitor Sysmon EID 7 ImageLoad events for `wmiutils.dll` loading in PowerShell processes, especially when combined with group discovery activity

5. **Process Chain Analysis** - Correlate parent-child process relationships where PowerShell spawns with WMI group query parameters from another PowerShell process

6. **System Discovery Process Sequence** - Detect sequences of discovery commands like `whoami.exe` followed by PowerShell WMI group queries within short time windows

7. **High-Privilege Group Enumeration** - Focus on WMI group queries executed by SYSTEM or other high-privilege accounts as shown in this dataset's process creation events
