# T1021.006-2: Windows Remote Management — Remote Code Execution with PS Credentials Using Invoke-Command

## Technique Context

T1021.006 Windows Remote Management represents a legitimate administrative protocol that attackers frequently abuse for lateral movement and remote code execution. WinRM uses HTTP/HTTPS to facilitate remote PowerShell sessions and command execution, making it particularly valuable for post-exploitation activities. The detection community focuses heavily on monitoring WinRM service activation, network connections to ports 5985/5986, wsmprovhost.exe process creation, and PowerShell remoting cmdlets like Invoke-Command. This technique is especially concerning because it leverages legitimate administrative tools, making it difficult to distinguish from normal IT operations without proper behavioral analysis.

## What This Dataset Contains

This dataset captures a complete WinRM-based remote code execution sequence using Invoke-Command. The attack flow begins with PowerShell EID 4104 script block showing `& {Enable-PSRemoting -Force\nInvoke-Command -ComputerName $env:COMPUTERNAME -ScriptBlock {whoami}}`. Security EID 4688 shows the initial PowerShell process creation with command line `"powershell.exe" & {Enable-PSRemoting -Force...}`, followed by extensive privilege token adjustments (EID 4703) enabling critical privileges including SeAssignPrimaryTokenPrivilege and SeImpersonatePrivilege.

The WinRM service activation is clearly visible through System EID 7040 showing "Background Intelligent Transfer Service service was changed from demand start to auto start" and EIDs 10148/10149 documenting WinRM listener configuration. System EIDs 113/114 show URL registration for WinRM endpoints on ports 5985 and 47001. Sysmon EID 1 captures the critical wsmprovhost.exe process creation with command line `C:\Windows\system32\wsmprovhost.exe -Embedding` under logon ID 0x4FC92AD.

Network activity is extensively logged through Sysmon EID 3 events showing TCP connections to ports 47001 and 5985, with multiple PowerShell processes connecting to localhost (0:0:0:0:0:0:0:1). Security EID 4624/4627/4672 events document Type 3 network logons with Kerberos authentication. The remote command execution is evidenced by Sysmon EID 1 showing whoami.exe creation from wsmprovhost.exe parent, and WMI EID 5860 monitoring wsmprovhost.exe process starts.

## What This Dataset Does Not Contain

This dataset represents a localhost loop-back scenario rather than true remote lateral movement between different hosts. The technique executes against $env:COMPUTERNAME (the local machine), which limits the network behavioral indicators that would be present in actual lateral movement scenarios. There are no cross-network authentication events, remote host enumeration, or inter-system credential delegation patterns that would typically accompany real WinRM lateral movement.

The PowerShell script block logging contains extensive cmdlet alias definitions and Enable-PSRemoting function definitions but lacks the more sophisticated PowerShell remoting patterns like New-PSSession, Enter-PSSession, or credential passing mechanisms that advanced attackers often employ. Additionally, while the dataset shows WinRM service configuration, it doesn't capture potential persistence mechanisms or advanced session management that sophisticated adversaries might implement.

## Assessment

This dataset provides excellent coverage for detecting WinRM-based remote code execution, particularly for the service enablement and basic Invoke-Command usage patterns. The combination of PowerShell script block logging, comprehensive process creation events, network connections, and system service changes creates a rich detection surface. The Security channel's complete authentication flow documentation combined with Sysmon's process and network telemetry offers multiple detection opportunities across different data sources.

However, the localhost execution scenario somewhat diminishes the dataset's value for detecting actual lateral movement patterns. While the technical WinRM mechanisms are identical, the network and authentication patterns differ significantly from genuine cross-host scenarios. The dataset is most valuable for detecting WinRM service abuse and PowerShell remoting cmdlet usage rather than comprehensive lateral movement behaviors.

## Detection Opportunities Present in This Data

1. **WinRM Service Activation** - System EID 7040 service start type changes to "auto start" combined with EIDs 10148/10149 for WinRM listener status changes
2. **PowerShell Remoting Cmdlets** - PowerShell EID 4104 script blocks containing "Enable-PSRemoting" and "Invoke-Command" with ComputerName parameters
3. **wsmprovhost.exe Process Creation** - Sysmon EID 1 showing wsmprovhost.exe with "-Embedding" parameter and correlation to WinRM network activity
4. **WinRM Network Connections** - Sysmon EID 3 TCP connections to ports 5985/47001 from PowerShell processes, especially with IPv6 localhost patterns
5. **HTTP URL Registration** - System EIDs 113/114 showing URL additions/removals for WinRM endpoints (http://+:5985/wsman/ and http://+:47001/wsman/)
6. **Cross-Process PowerShell Execution** - Sysmon EID 10 process access events showing wsmprovhost.exe accessing child processes with high privileges (0x1FFFFF)
7. **Token Privilege Escalation** - Security EID 4703 showing extensive privilege enables including SeImpersonatePrivilege and SeAssignPrimaryTokenPrivilege during WinRM sessions
8. **Remote Logon Pattern** - Security EID 4624 Type 3 logons with Kerberos authentication correlated with wsmprovhost.exe activity
9. **WMI Process Monitoring** - WMI EID 5860 queries specifically monitoring wsmprovhost.exe process starts
10. **PowerShell Process Chains** - Correlation of parent PowerShell processes spawning child processes through wsmprovhost.exe intermediary
