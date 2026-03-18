# T1087.002-18: Domain Account — Suspicious LAPS Attributes Query with Get-ADComputer all properties

## Technique Context

T1087.002 (Account Discovery: Domain Account) involves adversaries enumerating domain accounts to understand the domain structure and identify high-value targets. This specific test simulates a LAPS (Local Administrator Password Solution) focused reconnaissance technique where attackers query Active Directory computer objects with all properties to potentially harvest sensitive information including LAPS passwords stored in AD attributes like `ms-Mcs-AdmPwd`. The detection community focuses on monitoring for unusual PowerShell cmdlets that interact with Active Directory, particularly those using broad property queries (`-Properties *`) which can indicate reconnaissance activity. LAPS-specific enumeration is especially concerning as it directly targets privileged local administrator credentials.

## What This Dataset Contains

The dataset captures the execution of `Get-ADComputer $env:computername -Properties *` through PowerShell. Key telemetry includes:

**Security Channel Events:**
- Security 4688 process creation showing the PowerShell child process with command line: `"powershell.exe" & {Get-ADComputer $env:computername -Properties *}`
- Security 4703 token privilege adjustment showing elevated privileges being enabled including SeBackupPrivilege and SeRestorePrivilege
- Multiple Security 4689 process termination events for the PowerShell processes

**PowerShell Channel Events:**
- PowerShell 4103 command invocation for `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`
- PowerShell 4104 script block logging capturing the actual command: `Get-ADComputer $env:computername -Properties *`
- Script block logging also shows the command wrapped in execution context: `& {Get-ADComputer $env:computername -Properties *}`

**Sysmon Events:**
- Sysmon 1 process creation events for both `whoami.exe` and the PowerShell child process
- Sysmon 7 image load events showing .NET runtime and PowerShell automation assemblies being loaded
- Sysmon 10 process access events showing PowerShell accessing the whoami.exe process with full access rights (0x1FFFFF)
- Sysmon 11 file creation events for PowerShell profile data files
- Sysmon 17 named pipe creation events for PowerShell hosts

## What This Dataset Does Not Contain

This dataset does not contain the actual Active Directory query results or any LDAP network traffic that would show the AD server interaction. There are no network connection events (Sysmon EID 3) capturing the LDAP queries to domain controllers, which would be present in a real environment execution. The dataset also lacks any evidence of the Get-ADComputer cmdlet module being explicitly loaded, though this may be due to it being part of the default PowerShell session in a domain environment. Additionally, there are no DNS query events (Sysmon EID 22) that might show domain controller resolution.

## Assessment

This dataset provides excellent coverage for detecting the PowerShell-based execution of AD enumeration commands. The combination of Security 4688 command-line logging and PowerShell 4104 script block logging gives defenders multiple detection vectors for this technique. The Sysmon process creation events add additional context around the execution chain. However, the dataset's limitation is that it doesn't show the network-level indicators that would be present when this command actually queries Active Directory, making it primarily useful for detecting the local execution rather than the full reconnaissance activity.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Detection**: Monitor PowerShell 4104 events for `Get-ADComputer` cmdlet usage with wildcard properties (`-Properties *`)

2. **Command Line Analysis**: Detect Security 4688 events with command lines containing `Get-ADComputer` and broad property queries

3. **PowerShell Execution Policy Changes**: Alert on PowerShell 4103 events showing execution policy being set to Bypass in process scope

4. **Privilege Escalation Detection**: Monitor Security 4703 events where PowerShell processes enable sensitive privileges like SeBackupPrivilege

5. **Process Chain Analysis**: Correlate Sysmon 1 events showing PowerShell spawning from parent PowerShell processes for AD enumeration commands

6. **PowerShell Module Loading**: Track Sysmon 7 events for System.Management.Automation assembly loads in suspicious contexts

7. **AD Cmdlet Anomaly Detection**: Baseline normal Get-ADComputer usage patterns and alert on unusual property queries or frequency
