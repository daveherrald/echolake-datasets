# T1082-27: System Information Discovery — System Information Discovery with WMIC

## Technique Context

T1082 System Information Discovery is a fundamental Discovery tactic technique where adversaries gather detailed information about the compromised system's hardware, software, and configuration. This intelligence helps attackers understand their target environment, plan lateral movement, identify security controls, and tailor subsequent attacks. The technique is particularly valuable during initial reconnaissance phases and is commonly observed in both automated malware and human-operated intrusions.

WMIC (Windows Management Instrumentation Command-line) is a deprecated but still functional Windows utility that provides a command-line interface to WMI. Despite Microsoft's move toward PowerShell-based alternatives, WMIC remains popular among attackers due to its powerful querying capabilities and presence in older environments. Detection engineers focus on monitoring WMIC execution patterns, especially when querying multiple system components in rapid succession, as this often indicates automated reconnaissance rather than legitimate administration.

## What This Dataset Contains

This dataset captures a comprehensive WMIC-based system information gathering sequence executed via PowerShell. The attack chain begins with Security EID 4688 showing PowerShell (`powershell.exe`) spawning cmd.exe with an extensive command line containing multiple WMIC queries chained together:

`"cmd.exe" /c wmic cpu get name & wmic MEMPHYSICAL get MaxCapacity & wmic baseboard get product & wmic baseboard get version & wmic bios get SMBIOSBIOSVersion & wmic path win32_VideoController get name & wmic path win32_VideoController get DriverVersion & wmic path win32_VideoController get VideoModeDescription & wmic OS get Caption,OSArchitecture,Version & wmic DISKDRIVE get Caption & Get-WmiObject win32_bios`

Security events capture the complete process execution chain: powershell.exe → cmd.exe → multiple wmic.exe instances. Each WMIC process receives individual Security EID 4688/4689 events with specific command lines like `wmic cpu get name`, `wmic MEMPHYSICAL get MaxCapacity`, showing the systematic enumeration of CPU, memory, motherboard, BIOS, video controller, operating system, and disk drive information.

Sysmon provides rich complementary telemetry with EID 1 (Process Create) events capturing the cmd.exe execution and multiple EID 7 (Image Loaded) events showing WMIC processes loading WMI-related DLLs including `wmiutils.dll`, `amsi.dll`, and Windows Defender components. The cmd.exe process ultimately exits with status 0x1, while individual WMIC processes exit cleanly with status 0x0.

Security EID 4703 events document privilege adjustments for each WMIC process, showing elevation of powerful privileges including SeBackupPrivilege, SeRestorePrivilege, and SeLoadDriverPrivilege - highlighting the extensive system access WMIC can obtain.

## What This Dataset Does Not Contain

The dataset lacks WMI ETW (Event Tracing for Windows) events that would show the actual WMI queries and results returned. Windows Event Log doesn't capture the specific WMI namespace interactions or the data retrieved by each query, limiting visibility into what information was actually extracted.

The command line includes a PowerShell `Get-WmiObject win32_bios` command at the end, but there's no corresponding PowerShell process creation for this component, suggesting it may have failed or been truncated. The PowerShell channel contains only test framework-related boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual WMI query execution.

Network telemetry is absent, so any potential data exfiltration following the system enumeration would not be visible. The dataset also doesn't contain WMI operational logs that could provide additional context about the specific WMI providers accessed.

## Assessment

This dataset provides excellent process-level visibility into a systematic WMIC-based reconnaissance campaign. The combination of Security audit logs and Sysmon telemetry offers comprehensive coverage of process creation, command-line arguments, and privilege escalation patterns that are crucial for detecting this technique.

The data quality is particularly strong for building detections around process chains (powershell.exe → cmd.exe → multiple wmic.exe), command-line patterns with multiple chained WMIC queries, and rapid sequential execution of system information gathering tools. The Security EID 4703 privilege adjustment events add valuable context about the elevated access WMIC obtains.

However, the lack of WMI ETW logs limits the dataset's utility for understanding the actual data collected or building detections around specific WMI query patterns. For a complete picture of T1082 via WMIC, additional WMI operational logging would strengthen the dataset significantly.

## Detection Opportunities Present in This Data

1. **Sequential WMIC Process Creation** - Multiple wmic.exe processes spawned in rapid succession from the same parent cmd.exe process, indicating automated system enumeration rather than interactive administration.

2. **WMIC Command Line Patterns** - Detection of specific WMIC query patterns like `wmic cpu get name`, `wmic MEMPHYSICAL get MaxCapacity`, and `wmic OS get Caption,OSArchitecture,Version` that are commonly used for system profiling.

3. **Chained System Information Commands** - Single command line containing multiple WMIC queries concatenated with ampersands, indicating scripted reconnaissance activity.

4. **PowerShell to CMD to WMIC Process Chain** - Unusual execution path where PowerShell spawns cmd.exe which then launches multiple WMIC instances, suggesting obfuscation or evasion techniques.

5. **WMIC Privilege Escalation Events** - Security EID 4703 events showing WMIC processes obtaining high-privilege tokens with multiple sensitive privileges enabled simultaneously.

6. **Rapid WMI DLL Loading** - Sysmon EID 7 events showing multiple WMIC processes loading wmiutils.dll and other WMI-related libraries in quick succession.

7. **Comprehensive System Enumeration Signature** - Combined detection looking for processes querying CPU, memory, motherboard, BIOS, video, OS, and storage information within a short time window.

8. **WMIC with Defensive Evasion Indicators** - WMIC execution preceded by PowerShell execution policy bypass, suggesting attempts to evade script execution restrictions.
