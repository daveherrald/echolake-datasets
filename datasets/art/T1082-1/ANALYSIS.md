# T1082-1: System Information Discovery — System Information Discovery

## Technique Context

System Information Discovery (T1082) is a Discovery tactic technique where adversaries gather detailed information about the target system's configuration, hardware, software, and environment. This technique is fundamental to post-exploitation reconnaissance, helping attackers understand system capabilities, identify privilege escalation opportunities, and plan lateral movement. The technique typically involves querying system properties through built-in utilities like `systeminfo`, `whoami`, registry queries, and WMI calls.

The detection community focuses on monitoring execution of system information utilities, especially when invoked programmatically or in sequence. Key indicators include process creation events for reconnaissance binaries, command-line patterns that reveal enumeration intent, and WMI queries targeting system configuration classes.

## What This Dataset Contains

This dataset captures a comprehensive system information discovery sequence executed through PowerShell. The telemetry shows:

**Process Chain**: PowerShell (PID 2244) → cmd.exe (PID 3296) → systeminfo.exe (PID 6848) and reg.exe (PID 3888), with an additional PowerShell instance (PID 6420) executing whoami.exe (PID 5568).

**Key Command Lines**:
- `"cmd.exe" /c systeminfo & reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum`
- `systeminfo`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum`
- `"C:\Windows\system32\whoami.exe"`

**Sysmon Evidence**: Process creation events (EID 1) for all reconnaissance utilities, with Sysmon rules correctly tagging whoami.exe and systeminfo.exe under T1033 (System Owner/User Discovery) and cmd.exe/reg.exe under T1083 (File and Directory Discovery). Process access events (EID 10) show PowerShell obtaining PROCESS_ALL_ACCESS (0x1FFFFF) to spawned processes.

**Security Events**: Complete process lifecycle captured in Security 4688/4689 events with full command-line logging, showing the same process chain with successful exits (status 0x0).

**WMI Activity**: Single WMI event (EID 5858) shows systeminfo.exe querying `Win32_ComputerSystem` class in `root\cimv2`, typical for system information gathering.

## What This Dataset Does Not Contain

The dataset lacks the actual output or results from the reconnaissance commands, as these would appear in process stdout rather than Windows event logs. There are no registry access audit events (would require object access auditing), no file system queries beyond what's captured in process creation, and no network-based system discovery techniques. The PowerShell script block logging contains only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) rather than the actual discovery commands.

## Assessment

This dataset provides excellent telemetry for detecting system information discovery activities. The combination of Sysmon process creation with MITRE technique tagging, Security audit logs with command-line capture, and WMI operational events creates a comprehensive detection surface. The process chain clearly shows programmatic execution of multiple reconnaissance utilities in sequence, which is a strong indicator of automated discovery behavior rather than interactive administrator activity.

The data quality is high for building behavioral detections around reconnaissance tool usage patterns, parent-child process relationships, and command-line analysis. The WMI component adds valuable context about the underlying system queries being performed.

## Detection Opportunities Present in This Data

1. **Sequential reconnaissance tool execution** - Multiple system info utilities (systeminfo, whoami, reg) spawned within short time window from same PowerShell parent
2. **Command-line pattern matching** - Combined systeminfo and registry query in single cmd.exe command line suggests automated discovery script
3. **PowerShell process access behavior** - PROCESS_ALL_ACCESS (0x1FFFFF) granted to spawned reconnaissance processes, unusual for typical PowerShell usage
4. **WMI system class enumeration** - Win32_ComputerSystem queries from systeminfo.exe indicating hardware/OS discovery
5. **Registry key enumeration** - Specific query to `HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` reveals disk/storage discovery intent
6. **Parent process context** - Reconnaissance utilities launched from PowerShell rather than interactive command prompt suggests scripted execution
7. **Process creation clustering** - Multiple discovery-related processes created in rapid succession (7-second window) indicates automated enumeration
8. **AMSI DLL loading** - systeminfo.exe loading amsi.dll suggests potential script-based invocation under AMSI monitoring
