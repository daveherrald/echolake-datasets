# T1112-9: Modify Registry — BlackByte Ransomware Registry Changes - Powershell

## Technique Context

T1112 (Modify Registry) is a versatile technique used by adversaries for defense evasion and persistence. Attackers modify registry keys and values to disable security controls, establish persistence mechanisms, or alter system behavior. This particular test simulates registry modifications associated with BlackByte ransomware, which targets specific system policies to facilitate lateral movement and disable security features. The detection community focuses on monitoring registry writes to sensitive keys, particularly those affecting UAC policies, network connections, and file system behavior, as these are common targets for both ransomware and other malicious activities.

## What This Dataset Contains

This dataset captures a PowerShell-based execution of three specific registry modifications mimicking BlackByte ransomware behavior. The technique successfully executes through a child PowerShell process (PID 13136) spawned from the parent PowerShell process (PID 43976).

Security 4688 events show the command line: `"powershell.exe" & {New-ItemProperty \"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name LocalAccountTokenFilterPolicy -PropertyType DWord -Value 1 -Force; New-ItemProperty \"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name EnableLinkedConnections -PropertyType DWord -Value 1 -Force; New-ItemProperty \"HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem\" -Name LongPathsEnabled -PropertyType DWord -Value 1 -Force}`

PowerShell 4103/4104 events capture the actual cmdlet invocations with detailed parameter bindings for each `New-ItemProperty` call targeting the three registry locations.

Sysmon EID 13 events capture the successful registry writes:
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` set to DWORD (0x00000001)
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLinkedConnections` set to DWORD (0x00000001)

The dataset also includes standard PowerShell process telemetry including .NET runtime loading (EIDs 7), named pipe creation (EID 17), and process access events (EID 10).

## What This Dataset Does Not Contain

Notably missing is the Sysmon EID 13 registry write for the third modification (`HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled`), despite PowerShell logs indicating the cmdlet was invoked. This suggests either a timing issue with log collection or potential filtering in the Sysmon configuration. The PowerShell channel does not contain the actual script block for the LongPathsEnabled modification, though the command invocation is logged.

Missing are any Windows Defender alert events despite the real-time protection being active, indicating these registry modifications were not flagged as malicious. The sysmon-modular configuration's include-mode filtering means we don't capture Sysmon EID 1 events for the parent PowerShell process creation.

## Assessment

This dataset provides excellent coverage for detecting PowerShell-based registry modifications targeting UAC and system policies. The combination of Security 4688 command-line logging, PowerShell 4103/4104 cmdlet tracking, and Sysmon 13 registry monitoring creates multiple detection opportunities. The partial registry coverage (missing the third write) is a notable limitation but doesn't significantly impact the overall detection value. The data quality is high for building detections around both the specific registry keys modified and the broader pattern of PowerShell registry manipulation.

## Detection Opportunities Present in This Data

1. **Registry Policy Modification Detection** - Monitor Sysmon EID 13 for writes to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` and `EnableLinkedConnections` values being set to 1, which disable UAC remote restrictions and enable linked connections

2. **PowerShell New-ItemProperty Cmdlet Abuse** - Alert on PowerShell 4103 events showing `New-ItemProperty` cmdlet usage targeting sensitive registry paths, particularly system policies and security-related keys

3. **Command Line Registry Modification Pattern** - Detect Security 4688 events with command lines containing multiple `New-ItemProperty` calls targeting different registry hives in a single execution block

4. **BlackByte Ransomware Registry IOCs** - Create specific signatures for the combination of LocalAccountTokenFilterPolicy, EnableLinkedConnections, and LongPathsEnabled modifications occurring within a short timeframe

5. **PowerShell Script Block Suspicious Registry Operations** - Monitor PowerShell 4104 events for script blocks containing registry modification commands targeting system security policies, especially when executed with Force parameter

6. **Process Tree Analysis** - Correlate PowerShell parent-child relationships (Sysmon EID 1) with subsequent registry modifications to identify scripted attack patterns

7. **Privilege Escalation Preparation Detection** - Alert on registry modifications that prepare systems for privilege escalation or lateral movement, particularly UAC bypass configurations combined with network connection enablement
