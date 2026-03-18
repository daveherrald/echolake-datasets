# T1082-39: System Information Discovery — Discover OS Product Name via Registry

## Technique Context

T1082 System Information Discovery encompasses adversary efforts to gather information about the operating system and hardware of a system. This specific test (T1082-39) focuses on discovering the OS product name through direct registry query, a common technique used by malware and attackers to understand their target environment. Attackers use this information for environment awareness, compatibility checks for payloads, and to modify their behavior based on the target OS version. The detection community typically focuses on command-line patterns, registry access patterns, and process relationships when hunting for this technique.

## What This Dataset Contains

This dataset captures a PowerShell-initiated registry query operation with the following key evidence:

**Process Chain**: PowerShell (PID 13164) → cmd.exe (PID 13496) → reg.exe (PID 11820)

**Command Line Evidence** (Security 4688 events):
- `"cmd.exe" /c reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName`
- `reg  query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName`

**Sysmon Process Creation** (EID 1 events):
- Whoami.exe execution: `"C:\Windows\system32\whoami.exe"` (T1033 rule match)
- Cmd.exe execution with registry query command (T1059.003 rule match)
- Reg.exe execution targeting ProductName value (T1012 rule match)

**Process Access Events** (Sysmon EID 10):
- PowerShell accessing both whoami.exe and cmd.exe processes with full access rights (0x1FFFFF)

**PowerShell Telemetry**: Only test framework boilerplate (Set-ExecutionPolicy Bypass) - no script block logging of the actual discovery commands.

## What This Dataset Does Not Contain

This dataset lacks several important detection opportunities:

- **Registry Access Logging**: No Object Access auditing was enabled, so we don't have 4656/4663 events showing the actual registry key read
- **Detailed PowerShell Script Blocks**: The PowerShell channel only contains execution policy changes and error handling scriptblocks, not the commands that spawned the discovery processes
- **Network Activity**: No network connections from the discovery processes (as expected for local registry queries)
- **File System Artifacts**: No temporary files or output redirection captured

## Assessment

This dataset provides good coverage for process-based detection of registry discovery techniques. The Security 4688 events with command-line logging offer the strongest detection opportunities, capturing the exact registry query being performed. The Sysmon data adds valuable context with process relationships and rule-based categorization. However, the lack of Object Access auditing means we cannot detect more sophisticated registry access that bypasses command-line tools. For building detections around T1082, this data is quite valuable for command-line based approaches but incomplete for API-based registry access detection.

## Detection Opportunities Present in This Data

1. **Registry Query Command Lines**: Security 4688 events showing `reg.exe query` targeting system information registry keys like `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`

2. **Process Chain Analysis**: Sysmon EID 1 events revealing PowerShell → cmd.exe → reg.exe execution chain for registry discovery

3. **Suspicious Process Access**: Sysmon EID 10 events showing PowerShell accessing spawned discovery processes with full privileges (0x1FFFFF)

4. **Multiple Discovery Tool Usage**: Combined execution of whoami.exe and reg.exe from the same PowerShell parent, indicating reconnaissance activity

5. **Registry Tool Parameter Analysis**: Command-line parameters `/v ProductName` specifically targeting OS identification values

6. **Parent-Child Process Relationships**: Security 4688 Creator Process fields linking registry queries back to scripting engines

7. **Sysmon Rule Correlation**: Events tagged with T1012 (Query Registry), T1033 (System Owner/User Discovery), and T1059.003 (Windows Command Shell) rules providing pre-categorized suspicious activity
