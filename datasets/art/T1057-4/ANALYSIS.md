# T1057-4: Process Discovery — Process Discovery - get-wmiObject

## Technique Context

T1057 Process Discovery involves adversaries gathering information about running processes on a system to understand the environment, identify security tools, or find specific processes to target. The WMI approach using `Get-WmiObject` with the `Win32_Process` class is a common PowerShell method for process enumeration that provides detailed process information including process IDs, parent processes, command lines, and execution paths. This technique is frequently used by attackers during reconnaissance phases and by legitimate administrative tools, making it a challenging detection target that requires context-aware analysis. The detection community focuses on identifying unusual WMI queries, especially when executed in suspicious contexts or by unexpected processes.

## What This Dataset Contains

This dataset captures a PowerShell execution of `Get-WmiObject -class Win32_Process` with comprehensive telemetry across multiple data sources. The Security channel shows the process creation chain via EID 4688 events, including the parent PowerShell process (PID 0x2120) spawning a child PowerShell process (PID 0x2198) with command line `"powershell.exe" & {get-wmiObject -class Win32_Process}`. The technique triggers WMI Provider Host creation (WmiPrvSE.exe PID 0x22d0) spawned by svchost.exe with command line `C:\Windows\system32\wbem\wmiprvse.exe -Embedding`.

PowerShell telemetry includes EID 4103 CommandInvocation events showing `Get-WmiObject` execution with parameter binding for `Class: Win32_Process`, and EID 4104 script block logging capturing the actual command `{get-wmiObject -class Win32_Process}`. Sysmon provides rich process creation details via EID 1 events for both the PowerShell child process and WmiPrvSE.exe, along with EID 7 image load events showing WMI-related DLL loading (`wmiutils.dll`) tagged with `technique_id=T1047,technique_name=Windows Management Instrumentation`. Process access events (EID 10) show PowerShell accessing other processes with full access rights (GrantedAccess: 0x1FFFFF).

## What This Dataset Does Not Contain

The dataset lacks the actual WMI query results or output data that would show which processes were enumerated, as this information typically appears in application logs or PowerShell transcripts rather than security event logs. Network-related WMI activity is absent since this is a local query, and there are no ETW traces of the underlying WMI operations that would provide granular details about the CIM/WMI infrastructure interaction. The technique executes successfully without any Windows Defender blocks, so there are no security product intervention events that might appear in real-world scenarios where endpoint protection tools flag suspicious WMI usage.

## Assessment

This dataset provides excellent coverage for detecting WMI-based process discovery through multiple complementary data sources. The combination of Security 4688 process creation events, PowerShell operational logs capturing both command invocation and script block details, and Sysmon's process creation and image loading events creates a robust detection foundation. The WmiPrvSE.exe spawning is particularly valuable as it's a strong indicator of WMI activity that's harder to evade than PowerShell logging alone. The process access events add another detection dimension by showing the PowerShell process accessing other system processes, which could indicate process enumeration behavior.

## Detection Opportunities Present in This Data

1. **PowerShell WMI Process Query Detection** - Monitor EID 4103 CommandInvocation events for `Get-WmiObject` cmdlet execution with `Win32_Process` class parameter binding
2. **WMI Provider Host Spawning** - Detect EID 4688/Sysmon EID 1 process creation events for `WmiPrvSE.exe` with `-Embedding` parameter, especially when correlated with PowerShell activity
3. **PowerShell Script Block Analysis** - Alert on EID 4104 script blocks containing `get-wmiObject -class Win32_Process` or similar WMI process enumeration patterns
4. **WMI DLL Loading Pattern** - Monitor Sysmon EID 7 for `wmiutils.dll` loading in PowerShell processes as an indicator of WMI utilization
5. **Process Access with Full Rights** - Detect Sysmon EID 10 events where PowerShell processes access multiple other processes with high privilege levels (GrantedAccess: 0x1FFFFF)
6. **Command Line Process Discovery Pattern** - Search Security EID 4688 command lines for patterns like `powershell.*get-wmiobject.*Win32_Process` to catch this specific enumeration technique
7. **Cross-Process Correlation** - Build detection logic that correlates PowerShell process creation with subsequent WmiPrvSE.exe spawning within a short timeframe to identify WMI-based reconnaissance activity
