# T1201-10: Password Policy Discovery — Enumerate Active Directory Password Policy with get-addefaultdomainpasswordpolicy

## Technique Context

T1201 Password Policy Discovery involves adversaries attempting to access detailed information about the password policy used within an enterprise network. This information helps attackers understand complexity requirements, lockout policies, and other security controls that could impact their credential attacks. The `Get-ADDefaultDomainPasswordPolicy` PowerShell cmdlet is a legitimate Active Directory module function that queries domain controllers for password policy settings including minimum length, complexity requirements, lockout thresholds, and password history. Attackers often use this during initial reconnaissance phases to inform password spraying campaigns, brute force attacks, or social engineering efforts. Detection teams focus on monitoring for unauthorized use of AD enumeration cmdlets, especially when executed from unusual contexts or by non-administrative accounts performing reconnaissance activities.

## What This Dataset Contains

This dataset captures the execution of `Get-ADDefaultDomainPasswordPolicy` through PowerShell with comprehensive telemetry. The Security log shows the primary process creation in EID 4688: `"powershell.exe" & {get-addefaultdomainpasswordpolicy}` executed by NT AUTHORITY\SYSTEM. PowerShell script block logging in EID 4104 reveals the exact command structure: `& {get-addefaultdomainpasswordpolicy}` and `{get-addefaultdomainpasswordpolicy}`. Sysmon captures detailed process lineage with EID 1 showing the PowerShell process creation (PID 23560) with command line `"powershell.exe" & {get-addefaultdomainpasswordpolicy}` spawned from parent PowerShell process (PID 23088). The dataset includes extensive DLL loading events showing PowerShell initialization (.NET runtime components, System.Management.Automation), Windows Defender integration (MpOAV.dll, MpClient.dll), and process access events (EID 10) demonstrating normal PowerShell execution patterns. Named pipe creation events show PowerShell host initialization with pipes like `\PSHost.134179102739916146.23560.DefaultAppDomain.powershell`.

## What This Dataset Does Not Contain

The dataset lacks the actual output or results from the `Get-ADDefaultDomainPasswordPolicy` command — there are no events showing the retrieved password policy details, LDAP queries to domain controllers, or network traffic to AD servers. PowerShell transcript logs or output redirection that would capture the policy information are absent. The technique appears to have executed successfully (exit code 0x0 in Security EID 4689), but no events show the specific password policy data that would have been returned, such as minimum password length, complexity requirements, or lockout thresholds. There are no network connection events in Sysmon showing communication with domain controllers, and no additional authentication events that might occur during AD queries. The Active Directory module loading is not explicitly captured in the available events, though the technique's execution suggests it was available.

## Assessment

This dataset provides excellent visibility into the process execution and PowerShell activity surrounding password policy enumeration, but limited insight into the data exfiltration aspect of the technique. The process creation telemetry from both Security 4688 and Sysmon EID 1 offers strong detection foundations with clear command lines showing the specific Active Directory cmdlet usage. PowerShell script block logging captures the exact technique implementation, providing defenders with the precise commands used. The extensive Sysmon coverage of process relationships, DLL loading, and system interactions gives comprehensive context for behavioral analysis. However, the absence of network telemetry, LDAP query logs, or command output limits the dataset's utility for understanding the reconnaissance impact or developing data-focused detections. This is still highly valuable for process-based detection engineering focused on identifying unauthorized AD enumeration activities.

## Detection Opportunities Present in This Data

1. **Active Directory PowerShell Cmdlet Execution** - Security EID 4688 and Sysmon EID 1 with command lines containing `get-addefaultdomainpasswordpolicy` or other AD discovery cmdlets
2. **PowerShell Script Block Analysis** - PowerShell EID 4104 showing script blocks containing Active Directory enumeration functions like `Get-ADDefaultDomainPasswordPolicy`
3. **Reconnaissance Process Chain Detection** - Sysmon EID 1 showing PowerShell spawning with AD discovery commands from parent processes, especially from non-administrative or unexpected contexts
4. **PowerShell Module Loading Patterns** - Correlation of System.Management.Automation DLL loading (Sysmon EID 7) with subsequent AD cmdlet execution
5. **Behavioral Clustering** - Multiple PowerShell executions with AD discovery cmdlets within short time windows, indicating systematic reconnaissance
6. **Privilege Context Analysis** - AD enumeration cmdlets executed by accounts lacking legitimate administrative responsibilities for domain management
7. **PowerShell Execution Policy Bypass** - Security EID 4688 showing PowerShell with execution policy modifications followed by AD discovery commands
