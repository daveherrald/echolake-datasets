# T1087.002-10: Domain Account — Enumerate Active Directory for Unconstrained Delegation

## Technique Context

T1087.002 (Domain Account Discovery) involves enumerating domain user and computer accounts, often to identify privileged accounts or accounts with special permissions. This specific test (T1087.002-10) focuses on discovering objects with unconstrained delegation enabled—a high-value target for attackers since accounts with unconstrained delegation can impersonate any user to any service. The technique uses the Active Directory LDAP filter `(UserAccountControl:1.2.840.113556.1.4.803:=524288)` to identify objects where the `TRUSTED_FOR_DELEGATION` flag (524288) is set. Detection engineers typically focus on identifying LDAP queries with this specific UserAccountControl value, PowerShell cmdlets like `Get-ADObject` with delegation-related filters, and unusual domain enumeration patterns from non-administrative accounts.

## What This Dataset Contains

The dataset captures a PowerShell-based Active Directory enumeration using the `Get-ADObject` cmdlet. Security event 4688 shows the command execution: `"powershell.exe" & {Get-ADObject -LDAPFilter '(UserAccountControl:1.2.840.113556.1.4.803:=524288)' -Server $env:UserDnsDomain}`. PowerShell script block logging (EID 4104) reveals two critical scriptblocks: `& {Get-ADObject -LDAPFilter '(UserAccountControl:1.2.840.113556.1.4.803:=524288)' -Server $env:UserDnsDomain}` and the executed command `{Get-ADObject -LDAPFilter '(UserAccountControl:1.2.840.113556.1.4.803:=524288)' -Server $env:UserDnsDomain}`. 

Sysmon provides comprehensive process telemetry showing the PowerShell process chain: a parent powershell.exe (PID 41192) spawning a child powershell.exe (PID 41596) with the enumeration command. The process access events (EID 10) show PowerShell accessing both whoami.exe and the child PowerShell process with full access rights (0x1FFFFF), indicating normal PowerShell execution behavior. Security events document the complete process lifecycle with creation (4688) and termination (4689) events, plus privilege adjustment (4703) showing the PowerShell process enabling multiple system privileges.

## What This Dataset Does Not Contain

The dataset lacks the actual LDAP query traffic and responses—there are no DNS queries to domain controllers, no network connections to LDAP services, and no results indicating whether any objects with unconstrained delegation were discovered. The absence of network telemetry (Sysmon EIDs 3 or 22) suggests either the query failed, returned no results, or the network monitoring didn't capture the LDAP traffic. Additionally, there are no application-level logs from Active Directory services that would show the LDAP search being processed on the domain controller side. The dataset contains extensive PowerShell test framework boilerplate in the script block logging but minimal evidence of the actual AD module being loaded or the query results being processed.

## Assessment

This dataset provides excellent telemetry for detecting PowerShell-based Active Directory enumeration attempts, particularly those targeting unconstrained delegation. The combination of Security 4688 command-line logging and PowerShell 4104 script block logging creates strong detection opportunities by capturing both the process execution and the PowerShell commands themselves. The Sysmon process creation and access events add valuable context about the execution chain. However, the dataset's utility is limited by the lack of network telemetry and AD query results, making it difficult to assess whether the enumeration was successful or to understand the full scope of information gathered. The data sources captured here are sufficient for detecting the attempt but insufficient for determining the impact or success of the enumeration.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Detection**: Monitor EID 4104 events for the specific LDAP filter pattern `UserAccountControl:1.2.840.113556.1.4.803:=524288` which uniquely identifies unconstrained delegation enumeration attempts.

2. **Command Line Analysis**: Detect Security EID 4688 events where the command line contains `Get-ADObject` with `-LDAPFilter` parameters targeting UserAccountControl values, especially the delegation flag (524288).

3. **PowerShell AD Enumeration Pattern**: Correlate PowerShell process creation with script blocks containing `Get-ADObject` cmdlets and delegation-related LDAP filters to identify systematic AD reconnaissance.

4. **Process Chain Analysis**: Monitor for PowerShell parent-child relationships (via Sysmon EID 1 ParentProcessGuid) where child processes execute AD enumeration commands, indicating scripted or automated discovery activities.

5. **Privilege Escalation Context**: Analyze Security EID 4703 privilege adjustment events in conjunction with PowerShell AD queries to identify potentially unauthorized enumeration by accounts gaining excessive privileges.

6. **PowerShell Module Loading**: Combine image load events (Sysmon EID 7) showing PowerShell-related DLLs with subsequent AD cmdlet execution to detect the loading and use of Active Directory PowerShell modules for reconnaissance.
