# T1087.002-19: Domain Account — Suspicious LAPS Attributes Query with Get-ADComputer ms-Mcs-AdmPwd property

## Technique Context

T1087.002 (Domain Account Discovery) involves adversaries enumerating domain accounts to understand the environment and identify high-value targets. This specific test focuses on Local Administrator Password Solution (LAPS) attribute enumeration, a particularly sensitive discovery technique. LAPS stores local administrator passwords in Active Directory attributes `ms-Mcs-AdmPwd` (the password) and `ms-Mcs-AdmPwdExpirationTime` (expiration time). Attackers query these attributes to harvest local administrator passwords across domain-joined computers, enabling lateral movement with privileged credentials. The detection community focuses on monitoring Active Directory queries for LAPS-specific attributes, PowerShell usage targeting AD cmdlets, and unusual patterns of computer object enumeration that include sensitive properties.

## What This Dataset Contains

This dataset captures a PowerShell-based LAPS enumeration attempt that executed successfully. The core malicious activity appears in Security event 4688 showing the process creation: `"powershell.exe" & {Get-ADComputer $env:computername -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime}`. PowerShell script block logging (event 4104) captured the actual command: `Get-ADComputer $env:computername -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime`. The technique generated a complete process execution chain visible through Sysmon events: the parent PowerShell process (PID 15700) spawning a child PowerShell process (PID 14472) specifically for the LAPS query. Sysmon event 1 captured both the `whoami.exe` execution (likely for reconnaissance) and the main PowerShell command with full command line arguments. The dataset includes extensive .NET Framework and PowerShell module loading events (Sysmon event 7) showing the runtime environment initialization. Multiple named pipe creations (Sysmon event 17) indicate PowerShell host communication. Process access events (Sysmon event 10) show PowerShell accessing spawned child processes with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

The dataset lacks the actual Active Directory query results or network traffic showing LDAP queries to domain controllers, as the workstation may not have had proper LAPS deployment or domain connectivity during testing. No Sysmon network connection events (event 3) appear, which would typically show the LDAP connections to domain controllers. The PowerShell script block logging contains mostly test framework boilerplate rather than showing the full command execution flow or any error messages from failed AD queries. Registry access events that might show Active Directory client configuration or credential caching are absent. File system events showing potential credential harvesting or output file creation are not present. The dataset also lacks any Windows Security events related to Active Directory authentication or Kerberos ticket requests that would normally accompany legitimate AD cmdlet usage.

## Assessment

This dataset provides excellent visibility into the initial execution phases of LAPS enumeration attacks through comprehensive process creation and PowerShell logging. The Security event 4688 with command-line logging captures the exact malicious command with LAPS-specific attributes, making it ideal for developing command-line based detections. Sysmon's process creation, image loading, and process access events offer detailed execution context. However, the dataset's value is limited for detecting the network-level Active Directory interaction phase, which is often the most reliable detection point for this technique. The absence of actual LDAP query telemetry means you cannot build detections around the AD interaction patterns that would differentiate malicious LAPS queries from legitimate administrative access.

## Detection Opportunities Present in This Data

1. **PowerShell Command Line Detection**: Monitor Security event 4688 for PowerShell processes with command lines containing "Get-ADComputer" combined with "ms-Mcs-AdmPwd" or "ms-Mcs-AdmPwdExpirationTime" properties
2. **PowerShell Script Block Analysis**: Alert on PowerShell event 4104 script blocks containing LAPS-specific Active Directory attribute queries
3. **Process Chain Analysis**: Detect PowerShell parent processes spawning child PowerShell processes with AD cmdlet parameters using Sysmon event 1 correlation
4. **Suspicious PowerShell Module Loading**: Monitor Sysmon event 7 for System.Management.Automation.dll loading in conjunction with processes executing AD-related commands
5. **Named Pipe Monitoring**: Track Sysmon event 17 PowerShell named pipe creation patterns that correlate with LAPS enumeration timeframes
6. **Process Access Correlation**: Use Sysmon event 10 to identify PowerShell processes accessing spawned processes with full rights during AD enumeration activities
