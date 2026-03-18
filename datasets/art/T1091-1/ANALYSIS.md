# T1091-1: Replication Through Removable Media — USB Malware Spread Simulation

## Technique Context

T1091 (Replication Through Removable Media) represents a technique where adversaries use removable media like USB drives to move between systems and establish persistence. This technique is particularly significant for air-gapped networks or environments with limited network connectivity. Attackers commonly use USB devices infected with malware that auto-executes when inserted, or they may manually copy malicious files to removable drives discovered on compromised systems. The detection community focuses on monitoring removable media interactions, file creation patterns on external drives, WMI queries for drive enumeration, and process execution from removable media locations. This technique spans both Initial Access and Lateral Movement tactics, as USB devices can be the initial infection vector or a means of spreading within an environment.

## What This Dataset Contains

This dataset captures a PowerShell-based simulation that queries for removable drives and creates test files on any discovered USB devices. The core evidence appears in Security event 4688, showing PowerShell execution with the command line: `"powershell.exe" & {$RemovableDrives=@(); $RemovableDrives = Get-WmiObject -Class Win32_LogicalDisk -filter "drivetype=2" | select-object -expandproperty DeviceID; ForEach ($Drive in $RemovableDrives) {...}}`. The PowerShell script block logging in event 4103 captures the WMI query: `Get-WmiObject -Class Win32_LogicalDisk -filter "drivetype=2"`, which specifically searches for removable drive types. Sysmon provides complementary process creation data (EID 1) for multiple PowerShell instances and a WMI Provider Service (WmiPrvSE.exe) process. The dataset includes Sysmon image loads (EID 7) showing .NET runtime loading, WMI library loading (wmiutils.dll), and Windows Defender integration. Sysmon event 17 captures named pipe creation for PowerShell host communication, and events 10 show process access between PowerShell instances.

## What This Dataset Does Not Contain

The dataset lacks evidence of actual file creation on removable media, as no USB drives were present during the test execution. There are no Sysmon file creation events (EID 11) showing files written to external drive letters, no registry modifications related to USB device insertion, and no file system events from removable media paths. The WMI query executed successfully but returned no results since no removable drives were attached. Network activity related to potential command and control communication is absent, as this was a local simulation. The dataset also lacks process creation events for common USB-based attack vectors like autorun.inf execution or malware launching from removable media.

## Assessment

This dataset provides excellent visibility into the reconnaissance phase of T1091 attacks, particularly the WMI-based enumeration of removable drives. The Security and PowerShell logs capture the complete attack chain from the initial PowerShell execution through the WMI queries. However, the dataset's utility is limited for detection engineering focused on the actual malware spread component, since no removable media was present to demonstrate file creation or execution behaviors. The telemetry quality is high for detecting the enumeration techniques but incomplete for the full technique implementation. Detection engineers can use this data to build rules for WMI drive enumeration but would need additional datasets with actual USB interactions for comprehensive T1091 coverage.

## Detection Opportunities Present in This Data

1. **WMI Drive Enumeration Detection**: Monitor PowerShell event 4103 for `Get-WmiObject -Class Win32_LogicalDisk -filter "drivetype=2"` queries that specifically target removable drives
2. **PowerShell Script Block Analysis**: Detect PowerShell script blocks (EID 4104) containing removable drive enumeration logic combined with file creation loops
3. **Command Line Pattern Matching**: Build rules on Security 4688 events for command lines containing WMI drive enumeration with drivetype=2 filters
4. **WMI Provider Service Correlation**: Monitor Sysmon EID 1 for WmiPrvSE.exe process creation in temporal proximity to PowerShell executions targeting drive enumeration
5. **PowerShell Process Chaining**: Detect parent-child process relationships where PowerShell spawns additional PowerShell instances with drive enumeration parameters
6. **WMI Library Loading**: Monitor Sysmon EID 7 for wmiutils.dll loading in PowerShell processes as an indicator of WMI-based system reconnaissance
7. **Named Pipe Analysis**: Correlate Sysmon EID 17 PowerShell named pipe creation with concurrent WMI drive enumeration activities
