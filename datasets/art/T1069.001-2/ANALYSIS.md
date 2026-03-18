# T1069.001-2: Local Groups — Basic Permission Groups Discovery Windows (Local)

## Technique Context

T1069.001 (Local Groups) is a Discovery technique where adversaries enumerate local groups on a system to understand user permissions, administrative access, and potential privilege escalation paths. This technique is fundamental to post-exploitation reconnaissance — attackers need to map the local security landscape before moving laterally or escalating privileges. The most common implementation uses the built-in `net localgroup` command to list all local groups and their memberships, particularly targeting the Administrators group to identify high-privilege accounts. Detection communities focus on monitoring process creation events for net.exe executions with localgroup parameters, command-line argument analysis, and behavioral patterns of enumeration activities following initial access.

## What This Dataset Contains

This dataset captures a clean execution of local group enumeration through PowerShell invoking native Windows commands. The Security channel shows the complete process chain: PowerShell (PID 26040) spawning cmd.exe with the command line `"cmd.exe" /c net localgroup & net localgroup "Administrators"`, followed by two net.exe processes executing `net localgroup` and `net localgroup "Administrators"` respectively. Each net.exe process spawns its corresponding net1.exe helper process, showing the typical Windows net command architecture. Sysmon EID 1 events capture all process creations with full command lines and process relationships, tagged with relevant technique IDs including T1087.001 (Local Account) and T1018 (Remote System Discovery). The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no technique-specific script content. Process access events (Sysmon EID 10) show PowerShell accessing the child processes, and all processes exit cleanly with status 0x0.

## What This Dataset Does Not Contain

The dataset lacks the actual output of the net localgroup commands — the Security and Sysmon logs capture process execution but not the enumerated group information that would be displayed to the console. There are no Windows Event Log entries from the SAM (Security Account Manager) that might indicate group membership queries, as this technique uses standard API calls that don't generate additional audit events. The dataset also doesn't include any network traffic that might occur if the enumerated information were exfiltrated. Notably absent are any Windows Defender alerts or blocking actions, indicating this legitimate administrative command executed without triggering endpoint protection.

## Assessment

This dataset provides excellent telemetry for detecting T1069.001 through process-based monitoring. The Security channel's 4688 events with command-line logging and Sysmon's EID 1 ProcessCreate events both capture the essential indicators: net.exe execution with "localgroup" parameters. The complete process tree from PowerShell → cmd.exe → net.exe → net1.exe is well-documented with precise timestamps and parent-child relationships. The data sources here are ideal for building detections based on process creation, command-line analysis, and parent process relationships. However, the dataset would be stronger with additional context like user account enumeration (net user) commands or follow-on lateral movement attempts that typically accompany group enumeration in real attack scenarios.

## Detection Opportunities Present in This Data

1. **Net Command Group Enumeration** - Security EID 4688 and Sysmon EID 1 showing net.exe with command line containing "localgroup" parameter, particularly when combined with specific group names like "Administrators"

2. **Process Chain Analysis** - PowerShell spawning cmd.exe which spawns net.exe processes, indicating potential scripted enumeration rather than interactive administrative activity

3. **Rapid Sequential Group Queries** - Multiple net.exe processes executing within seconds targeting different groups (general localgroup enumeration followed by specific Administrators group query)

4. **Parent Process Context** - Net.exe processes spawned by non-administrative tools like PowerShell or cmd.exe rather than typical administrative interfaces

5. **Net/Net1 Process Pairing** - Detection of the characteristic net.exe → net1.exe process relationship that indicates genuine Windows net command execution versus potential masquerading

6. **Privilege Context Monitoring** - System-level execution of enumeration commands which may indicate compromised high-privilege accounts conducting reconnaissance
