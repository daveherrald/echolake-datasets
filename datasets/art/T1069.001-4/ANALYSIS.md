# T1069.001-4: Local Groups — SharpHound3 - LocalAdmin

## Technique Context

T1069.001 (Local Groups) is a discovery technique where adversaries enumerate local group memberships to understand user privileges and potential escalation paths. Local group enumeration is fundamental to post-exploitation reconnaissance, particularly identifying members of high-privilege groups like Administrators, Backup Operators, and Remote Desktop Users.

SharpHound is BloodHound's data collection tool, designed specifically for Active Directory enumeration and attack path analysis. The LocalAdmin collection method focuses on identifying local administrator group memberships across domain systems — critical intelligence for lateral movement planning. This technique is extensively used by red teams and real-world attackers because local administrator rights enable credential access, persistence mechanisms, and further network traversal.

Detection engineering focuses on identifying the network enumeration patterns, LDAP queries, and local group interrogation APIs that tools like SharpHound generate during collection operations.

## What This Dataset Contains

This dataset captures a SharpHound execution using the LocalAdmin collection method. The key evidence appears in Security event 4688, showing the PowerShell command line that executes SharpHound:

`"powershell.exe" & {New-Item -Path \""$env:TEMP\SharpHound\\"" -ItemType Directory > $null & \""C:\AtomicRedTeam\atomics\..\ExternalPayloads\SharpHound.exe\"" -d \""$env:UserDnsDomain\"" --CollectionMethod LocalAdmin --NoSaveCache --OutputDirectory \""$env:TEMP\SharpHound\\""}"`

The execution creates a temporary directory structure visible in Sysmon event 11: `C:\Windows\Temp\SharpHound` with creation time `2026-03-13 18:36:44.551`. However, notably absent from this dataset is any Sysmon ProcessCreate event for SharpHound.exe itself, despite the command line clearly attempting to execute it.

PowerShell telemetry shows the execution test framework with script block logging (events 4104) capturing the actual command construction, while Security events 4688/4689 track the PowerShell process lifecycle and privilege adjustments (event 4703 showing multiple sensitive privileges enabled).

The Sysmon events primarily capture PowerShell .NET assembly loading and Windows Defender DLL interactions, suggesting the endpoint protection system was actively monitoring the execution.

## What This Dataset Does Not Contain

This dataset lacks the most critical evidence: there are no Sysmon ProcessCreate events for SharpHound.exe execution, no network connection events showing LDAP queries or SMB enumeration, and no additional file creation events showing SharpHound's typical output files (.zip archives containing JSON data). 

The absence of SharpHound.exe process creation suggests either Windows Defender blocked the execution before the binary could start, the sysmon-modular configuration filtered the process (though SharpHound.exe should match suspicious binary patterns), or the tool failed to execute properly. The command line shows an exit status of 0x1 for one of the cmd.exe processes, indicating an error condition.

There are also no DNS resolution events, outbound network connections, or LDAP query telemetry that would typically accompany successful SharpHound LocalAdmin collection. The dataset contains no evidence of the actual discovery technique being performed — only the attempt to execute the tool.

## Assessment

This dataset provides limited value for detection engineering of T1069.001 Local Groups discovery. While it captures the execution attempt and command line artifacts that could trigger detections, it lacks the core network and API behavior that defines this technique. 

The PowerShell script block logging and Security 4688 events with command-line auditing provide good coverage for detecting SharpHound execution attempts. However, without the actual enumeration behavior, process execution, or network activity, this dataset cannot inform detections of the discovery activities themselves.

The dataset would be significantly more valuable if it contained successful SharpHound execution with network connections, process creation events, and output file generation that represent the actual technique implementation rather than just the launch attempt.

## Detection Opportunities Present in This Data

1. **SharpHound Command Line Detection** - Security 4688 events containing "SharpHound.exe" with "--CollectionMethod LocalAdmin" parameters indicate specific AD enumeration tooling

2. **Suspicious Directory Creation** - Sysmon 11 events showing creation of temporary directories with "SharpHound" in the path suggest preparation for data collection output

3. **PowerShell Script Block Analysis** - Event 4104 capturing the full SharpHound execution command within PowerShell script blocks, including parameter parsing for collection methods

4. **Privilege Escalation Context** - Security 4703 events showing multiple sensitive privileges (SeBackupPrivilege, SeRestorePrivilege, etc.) enabled in conjunction with enumeration tool execution

5. **Tool Staging Detection** - File path patterns in command lines referencing "ExternalPayloads\SharpHound.exe" indicate organized red team tool deployment structures
