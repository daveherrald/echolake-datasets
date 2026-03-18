# T1082-28: System Information Discovery — System Information Discovery

## Technique Context

System Information Discovery (T1082) is a fundamental discovery technique where adversaries gather information about the operating system, hardware, and configuration of compromised systems. This intelligence enables attackers to understand their environment, identify privilege escalation opportunities, locate valuable data, and adapt their tools and techniques to the target system. Common methods include executing built-in utilities like `systeminfo`, `wmic`, or PowerShell cmdlets to enumerate OS details, hardware specifications, installed software, and network configurations.

Detection engineering teams focus on monitoring execution of system information gathering tools, unusual PowerShell activity, WMI queries for system data, and processes that enumerate multiple system components in rapid succession. The challenge lies in distinguishing legitimate administrative activity from reconnaissance behavior, often requiring behavioral analytics and context awareness.

## What This Dataset Contains

This dataset captures a comprehensive system information discovery operation executed via a VBScript (`gatherNetworkInfo.vbs`) that spawns multiple child processes to collect system details. The primary evidence includes:

**Process Chain**: PowerShell → cmd.exe → wscript.exe → multiple cmd.exe processes spawning system utilities
- Security EID 4688 shows `wscript.exe C:\Windows\System32\gatherNetworkInfo.vbs` launched from cmd.exe
- Security EID 4688 captures `systeminfo` execution: `systeminfo >>config\osinfo.txt`
- Security EID 4688 shows environment variable enumeration: `set processor >>config\osinfo.txt` and `set u >>config\osinfo.txt`

**PowerShell System Discovery**: The dataset contains extensive PowerShell EID 4104 script block logging showing network adapter enumeration:
```
$net_adapter=(Get-NetAdapter -IncludeHidden); $output= ($net_adapter); $output += ($net_adapter | fl *); $output += (Get-NetAdapterAdvancedProperty | fl); $net_adapter_bindings=(Get-NetAdapterBinding -IncludeHidden); $output += ($net_adapter_bindings); $output += ($net_adapter_bindings | fl); $output += (Get-NetIpConfiguration -Detailed)
```

**Sysmon Process Creation**: Sysmon EID 1 events show system enumeration tools:
- `whoami.exe` for user context discovery (T1033)
- `systeminfo.exe` for OS and hardware details
- `tasklist.exe /svc` for running processes and services (T1057)

**Registry Discovery**: Multiple Security EID 4688 events show `reg.exe export` commands targeting authentication-related registry keys like credential providers and network service configurations.

**WMI Activity**: WMI EID 5858 shows `Win32_TimeZone` enumeration from systeminfo.exe, indicating WMI-based system discovery.

**File Creation**: Sysmon EID 11 events document output files creation in `C:\Windows\Temp\config\` including `osinfo.txt`, `battery-report.html`, and various registry exports.

## What This Dataset Does Not Contain

The dataset lacks several common T1082 variations:
- No direct WMI command-line queries using `wmic.exe`
- Missing hardware-specific enumeration commands like `dxdiag` or driver queries
- No PowerShell `Get-ComputerInfo` or `Get-WmiObject Win32_*` cmdlets in the captured script blocks
- Limited process discovery telemetry beyond the basic tasklist execution
- No evidence of privilege enumeration commands like `whoami /priv` or group membership queries

The Sysmon ProcessCreate filtering means many standard Windows utilities that might be involved in system discovery aren't captured as Sysmon EID 1 events, relying instead on Security EID 4688 for process visibility.

## Assessment

This dataset provides excellent coverage for script-based system information discovery, particularly VBScript-orchestrated enumeration campaigns. The combination of Security process creation events, PowerShell script block logging, and Sysmon file creation monitoring creates a comprehensive view of the discovery operation. The registry export activities and network adapter enumeration through PowerShell represent realistic advanced reconnaissance techniques.

The data quality is strong for building behavioral detections around rapid system enumeration sequences and script-driven discovery frameworks. However, it's less useful for detecting simple, one-off utility executions or purely WMI-based discovery techniques. The dataset excels at showing how modern attackers chain multiple discovery methods together in automated scripts.

## Detection Opportunities Present in This Data

1. **VBScript System Enumeration**: Monitor for wscript.exe executing system information gathering scripts, especially with file output redirection to temporary directories (Security EID 4688, Sysmon EID 1)

2. **Rapid System Utility Sequence**: Detect multiple system information tools (systeminfo, whoami, tasklist, reg export) executed in quick succession from the same parent process tree (Security EID 4688 correlation)

3. **PowerShell Network Discovery**: Alert on PowerShell script blocks containing Get-NetAdapter, Get-NetAdapterAdvancedProperty, and Get-NetIpConfiguration cmdlets with comprehensive parameter usage (PowerShell EID 4104)

4. **Registry Authentication Enumeration**: Monitor for reg.exe export operations targeting credential provider registry keys and authentication-related hives (Security EID 4688 with specific command-line patterns)

5. **Temp Directory System Discovery**: Detect file creation patterns in temporary directories with system information filenames like osinfo.txt, combined with process execution of discovery tools (Sysmon EID 11 + EID 1 correlation)

6. **WMI System Queries**: Monitor WMI operations against Win32_TimeZone and other system information classes, especially when correlated with other discovery activity (WMI EID 5858)

7. **Script-Based Discovery Framework**: Identify parent processes spawning multiple child processes for system enumeration, with consistent working directory and output file patterns (Security EID 4688 process tree analysis)
