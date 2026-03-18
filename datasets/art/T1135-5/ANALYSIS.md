# T1135-5: Network Share Discovery — Network Share Discovery PowerShell

## Technique Context

T1135 Network Share Discovery is a discovery technique where adversaries enumerate network shares to understand available resources and potential lateral movement targets. The technique is commonly used during the reconnaissance phase to map network file shares, identify accessible systems, and locate sensitive data repositories. Attackers frequently employ PowerShell cmdlets like `Get-SmbShare`, `Get-WmiObject`, or `net share` to enumerate both local and remote shares. The detection community focuses on monitoring for these enumeration commands, especially when executed by unexpected processes or users, as share discovery often precedes data exfiltration or lateral movement activities.

## What This Dataset Contains

This dataset captures a PowerShell-based network share discovery execution using the `Get-SmbShare` cmdlet. The core technique evidence appears in several key locations:

- **Security Event 4688**: PowerShell process creation with command line `"powershell.exe" & {get-smbshare}` (Process ID 31812)
- **PowerShell Event 4104**: Script block showing the actual execution `& {get-smbshare}` (ScriptBlock ID: 800702af-5ec5-4674-b5a6-31fbfbae350e)
- **PowerShell Event 4103**: CommandInvocation showing `Get-SmbShare` execution with parameters including `IncludeHidden=False`, `ThrottleLimit=0`, and `AsJob=False`
- **Sysmon Event 1**: Process creation for the PowerShell child process executing the share discovery command

The dataset also captures the PowerShell module loading behavior, including the SmbShare module initialization with various cmdlet aliases being set (`ssmbp`, `gsmbd`, `gsmbscp`, `esmbd`, `dsmbd`) and localization data loading. The execution occurs under NT AUTHORITY\SYSTEM context, which is typical for Atomic Red Team test executions.

## What This Dataset Does Not Contain

The dataset lacks several elements that would typically accompany network share discovery in real-world scenarios:

- **Network traffic**: No Sysmon Event 3 (Network Connection) events are present, suggesting the `Get-SmbShare` command only enumerated local shares rather than attempting remote share discovery
- **SMB protocol activity**: No evidence of SMB/CIFS network communications that would indicate remote share enumeration
- **Output capture**: The actual results of the share enumeration are not captured in the logs
- **Follow-on activity**: No subsequent file access attempts, directory listings, or data staging activities that often follow share discovery
- **WMI queries**: No WMI-based share discovery methods (like `Get-WmiObject -Class Win32_Share`) are captured

## Assessment

This dataset provides excellent coverage for detecting PowerShell-based local share discovery using the `Get-SmbShare` cmdlet. The PowerShell operational logs (Events 4103/4104) capture the complete command execution with parameters, while Security Event 4688 provides process-level visibility with command lines. The Sysmon data adds process ancestry and timing information. However, the dataset is limited to local share discovery only, as evidenced by the lack of network connections. For comprehensive T1135 detection development, additional datasets covering remote share enumeration and alternative discovery methods (net.exe, WMI queries) would be valuable.

## Detection Opportunities Present in This Data

1. **PowerShell Share Discovery Cmdlet**: Monitor PowerShell Event 4103 for `CommandName = Get-SmbShare` executions, particularly from unexpected users or processes
2. **PowerShell Script Block Analysis**: Alert on Event 4104 script blocks containing `get-smbshare` or similar share enumeration commands
3. **Process Command Line Detection**: Monitor Security Event 4688 for powershell.exe processes with command lines containing share discovery patterns like `get-smbshare`
4. **SMB Module Loading**: Track PowerShell module loading events that initialize SMB-related functionality, especially when combined with subsequent share enumeration
5. **Parent-Child Process Relationships**: Monitor Sysmon Event 1 for PowerShell child processes spawned with share discovery command lines, correlating with parent PowerShell execution context
6. **Execution Context Anomalies**: Flag share discovery commands executed under high-privilege accounts (SYSTEM, service accounts) outside of expected administrative activities
7. **PowerShell Parameter Analysis**: Examine PowerShell Event 4103 parameter bindings for share discovery cmdlets, particularly noting parameters like `IncludeHidden=True` that may indicate advanced reconnaissance
