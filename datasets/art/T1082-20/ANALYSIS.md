# T1082-20: System Information Discovery — WinPwn - RBCD-Check

## Technique Context

T1082 System Information Discovery is a fundamental reconnaissance technique where adversaries gather information about the operating system, hardware, and software configuration of compromised systems. This intelligence helps attackers understand their environment, identify potential privilege escalation paths, and plan lateral movement. Common methods include executing built-in utilities like `systeminfo`, `whoami`, `wmic`, or leveraging PowerShell cmdlets to enumerate system details.

The detection community focuses on monitoring for suspicious process execution patterns, particularly when multiple system discovery commands execute in rapid succession. PowerShell-based discovery activities are especially concerning as they can indicate automated toolkits or post-exploitation frameworks gathering environmental intelligence.

## What This Dataset Contains

This test executed WinPwn's RBCD-Check function, which attempts to download and execute a PowerShell reconnaissance framework but was blocked by Windows Defender. The dataset captures:

**Process Chain**: PowerShell spawns whoami.exe (PID 18664) and creates a child PowerShell process (PID 18528) with the command line `"powershell.exe" & {$S3cur3Th1sSh1t_repo = 'https://raw.githubusercontent.com/S3cur3Th1sSh1t'...}`

**Network Activity**: Sysmon EID 22 shows DNS resolution for `raw.githubusercontent.com` and EID 3 captures the TCP connection to 185.199.108.133:443, indicating the attempt to download the WinPwn framework.

**Defender Blocking**: PowerShell EID 4100 shows "This script contains malicious content and has been blocked by your antivirus software" with error ID `ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand`.

**System Discovery**: Sysmon EID 1 captures whoami.exe execution with rule name `technique_id=T1033,technique_name=System Owner/User Discovery`, demonstrating basic user enumeration.

**Process Access**: Sysmon EID 10 shows the parent PowerShell process accessing both whoami.exe and the child PowerShell process with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

**Successful Framework Execution**: The WinPwn framework never fully loaded due to Windows Defender intervention, so we don't see the typical system enumeration commands (systeminfo, net commands, registry queries) that would normally follow.

**Complete RBCD Analysis**: The Resource-Based Constrained Delegation check functionality was blocked before execution, missing the Active Directory enumeration telemetry this technique would generate in an unprotected environment.

**Sysmon ProcessCreate Coverage**: The sysmon-modular config's include-mode filtering means many subprocess creations aren't captured — only whoami.exe and the child PowerShell process appear in Sysmon EID 1 events.

## Assessment

This dataset provides excellent visibility into the initial stages of PowerShell-based reconnaissance toolkit deployment but limited insight into successful system discovery activities. The combination of Security 4688 events with full command-line logging, Sysmon network monitoring, and PowerShell script block logging creates strong detection coverage for this attack pattern.

The Windows Defender blocking behavior is particularly valuable, showing how modern endpoint protection interacts with malicious PowerShell execution while still generating useful forensic artifacts. However, the blocked execution limits the dataset's utility for understanding the full scope of system discovery activities that successful attacks would generate.

## Detection Opportunities Present in This Data

1. **PowerShell Web Download Pattern**: Detect `new-object net.webclient).downloadstring()` patterns in Security 4688 command lines and PowerShell 4104 script blocks.

2. **Malicious GitHub Repository Access**: Monitor DNS queries and network connections to known offensive security repositories like S3cur3Th1sSh1t's WinPwn.

3. **AMSI Blocking Events**: PowerShell 4100 events with "ScriptContainedMaliciousContent" indicate real-time malware blocking and should trigger high-priority alerts.

4. **Reconnaissance Process Chains**: Sequential execution of discovery utilities (whoami, systeminfo, etc.) from PowerShell parent processes, captured in Security 4688 events.

5. **Suspicious PowerShell Process Access**: Sysmon EID 10 events showing PowerShell processes opening other processes with full access rights may indicate injection attempts or process monitoring.

6. **Named Pipe Creation Patterns**: Sysmon EID 17 pipe creation events with PowerShell-specific naming conventions can identify PowerShell execution contexts.

7. **Rapid System Discovery Sequence**: Multiple T1033/T1082 technique detections within short time windows suggest automated reconnaissance toolkits.
