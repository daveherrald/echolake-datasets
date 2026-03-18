# T1047-3: Windows Management Instrumentation — WMI Reconnaissance Software

## Technique Context

Windows Management Instrumentation (WMI) is a powerful Windows administration feature that provides standardized interfaces for local and remote system management. Attackers commonly abuse WMI for reconnaissance, lateral movement, persistence, and execution. The WMI command-line utility (WMIC.exe) is particularly attractive to attackers because it's a legitimate Microsoft tool that can query extensive system information, execute commands remotely, and often bypasses basic security controls.

This specific test (T1047-3) demonstrates WMI reconnaissance capabilities by using WMIC to gather installed software information via the Win32_QuickFixEngineering class. This is a classic information gathering technique that helps attackers understand patch levels and potential vulnerabilities on a target system. Detection engineers focus on monitoring WMIC.exe execution, WMI namespace queries, and the specific WQL queries being performed.

## What This Dataset Contains

The dataset captures a complete WMI reconnaissance execution chain initiated from PowerShell. The core technique execution shows:

**Process Chain:** PowerShell → cmd.exe → WMIC.exe executing `wmic qfe get description,installedOn /format:csv` (Security EID 4688)

**Key WMI Evidence:**
- WMIC.exe process creation with command line showing Quick Fix Engineering query
- WMI-related DLL loading including `C:\Windows\System32\wbem\wmiutils.dll` (Sysmon EID 7)
- AMSI.dll loading in the WMIC process, indicating Windows Defender's behavioral monitoring
- PowerShell process access events (Sysmon EID 10) with full access rights (0x1FFFFF) to spawned child processes

**Supporting Telemetry:**
- Multiple PowerShell processes spawning and the associated .NET runtime loading
- Windows Defender DLL injections (MpOAV.dll, MpClient.dll) in all PowerShell processes
- Named pipe creation for PowerShell inter-process communication
- Process privilege adjustments for both PowerShell and WMIC (Security EID 4703)

The technique successfully executes without any blocking, as evidenced by clean exit statuses (0x0) for all processes.

## What This Dataset Does Not Contain

**Missing WMI-Specific Events:** The dataset lacks WMI operational logs (Microsoft-Windows-WMI-Activity/Operational) that would show the actual WQL query execution, WMI provider connections, and namespace access patterns. These logs are critical for detecting WMI abuse but are not enabled by default.

**No Network Activity:** Since this is a local reconnaissance query, there are no network connections or remote WMI activities that would generate additional network-based telemetry.

**Limited Registry Activity:** WMI configuration and COM object registration events are not captured, though these could provide additional detection opportunities for WMI monitoring.

## Assessment

This dataset provides good coverage for detecting WMIC-based reconnaissance at the process execution level. The Security event logs with command-line auditing capture the specific WMI query being executed, which is the primary detection opportunity for this technique. The Sysmon events add valuable context around process relationships, DLL loading patterns, and process access behaviors.

However, the absence of WMI operational logs significantly limits the depth of WMI-specific detection opportunities. In production environments, enabling WMI activity logging would provide much richer telemetry for detecting sophisticated WMI abuse beyond simple WMIC.exe execution.

The dataset effectively demonstrates how legitimate system administration tools can be monitored through standard Windows logging, even when specialized logging (like WMI operational events) is not available.

## Detection Opportunities Present in This Data

1. **WMIC.exe execution with reconnaissance-oriented command lines** - Security EID 4688 with CommandLine containing "qfe get" or other system information queries

2. **PowerShell spawning system reconnaissance tools** - Process creation events where powershell.exe is the parent of wmic.exe, whoami.exe, or similar enumeration utilities

3. **WMI utility DLL loading patterns** - Sysmon EID 7 showing wmiutils.dll loading in processes, indicating WMI API usage

4. **Suspicious process access from PowerShell** - Sysmon EID 10 events where PowerShell accesses newly spawned child processes with full access rights (0x1FFFFF)

5. **Multiple PowerShell processes with system privileges** - Pattern of multiple powershell.exe processes running as NT AUTHORITY\SYSTEM within short time windows

6. **AMSI loading in system utilities** - Sysmon EID 7 showing amsi.dll loading in WMIC.exe, indicating potential script-based execution paths

7. **Named pipe creation patterns** - Sysmon EID 17 showing PowerShell creating communication pipes, often associated with automation frameworks
