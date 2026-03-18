# T1112-89: Modify Registry — Abusing MyComputer Disk Backup Path for Persistence

## Technique Context

T1112 (Modify Registry) is a fundamental technique used by attackers to achieve persistence and defense evasion by manipulating Windows registry values. This specific test demonstrates an uncommon persistence technique that abuses the Windows Explorer "MyComputer\BackupPath" registry key. When this key is set, Windows Explorer will automatically execute the specified program when users navigate to certain locations in the file system, providing a relatively stealthy persistence mechanism.

The detection community typically focuses on monitoring registry modifications to well-known persistence locations (Run keys, Winlogon, Services), but this technique exploits a less commonly monitored Windows Explorer feature. Attackers value this approach because it doesn't require writing files to startup folders or modifying obvious autorun locations, potentially evading detection rules focused on traditional persistence mechanisms.

## What This Dataset Contains

This dataset captures the complete execution of the MyComputer BackupPath persistence technique through multiple telemetry sources. The primary technique implementation occurs via Security event 4688 showing cmd.exe execution with the command line `"cmd.exe" /c reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\BackupPath" /t REG_EXPAND_SZ /d "%systemroot%\system32\notepad.exe" /f`, followed by Sysmon event 1 capturing reg.exe with the expanded command `reg  add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\BackupPath" /t REG_EXPAND_SZ /d "C:\Windows\system32\notepad.exe" /f`.

The process chain shows PowerShell (PID 18776) spawning cmd.exe (PID 12456), which then spawns reg.exe (PID 43836) to perform the actual registry modification. Sysmon captures all three processes in the chain with detailed command lines and process relationships. Additional context includes whoami.exe execution for system enumeration and multiple Sysmon process access events (Event ID 10) showing PowerShell accessing the spawned child processes.

The PowerShell channel contains only test framework boilerplate (Set-ExecutionPolicy Bypass commands and error handling scriptblocks), providing no additional insight into the technique itself.

## What This Dataset Does Not Contain

This dataset lacks actual registry modification events - neither Sysmon registry events (Event IDs 12, 13, 14) nor Security registry auditing events are present, likely because the audit policy doesn't include object access auditing for registry operations. The reg.exe process completes successfully (exit status 0x0), indicating the registry modification was performed, but the actual registry write operation isn't captured in the telemetry.

Additionally, the dataset doesn't contain any evidence of the persistence mechanism being triggered or tested - it only shows the installation phase of the technique. Network activity, file system changes beyond PowerShell profile files, and Windows Defender's response to the registry modification are not captured.

## Assessment

This dataset provides good coverage of the process execution aspects of registry-based persistence installation but lacks visibility into the actual registry changes, which are the core artifacts for this technique. The process telemetry is comprehensive, showing the complete command execution chain from PowerShell through cmd.exe to reg.exe with full command lines and parent-child relationships.

The data quality is strong for building detections based on process creation patterns and command-line analysis, but insufficient for detections based on registry modifications themselves. For a complete T1112 detection capability, this would need to be supplemented with registry auditing or Sysmon registry monitoring events.

## Detection Opportunities Present in This Data

1. **Registry modification via reg.exe**: Security event 4688 and Sysmon event 1 showing reg.exe with command lines containing "add" operations to HKLM registry paths, particularly targeting Explorer-related keys

2. **MyComputer BackupPath specific pattern**: Command line pattern matching for "MyComputer\BackupPath" registry path modifications, which is an uncommon but known persistence mechanism

3. **PowerShell spawning registry tools**: Process creation events showing powershell.exe as parent process for cmd.exe or reg.exe, particularly when combined with registry modification commands

4. **Command shell proxy execution**: Detection of cmd.exe with /c parameter executing registry commands, spawned by scripting engines like PowerShell

5. **Registry tool usage from system context**: reg.exe execution under NT AUTHORITY\SYSTEM context performing add operations to HKLM, which may indicate automated or scripted persistence installation

6. **Process access patterns**: Sysmon event 10 showing PowerShell accessing spawned child processes with high-privilege access (0x1FFFFF), potentially indicating process monitoring or control behavior
