# T1069.002-7: Domain Groups — Enumerate Users Not Requiring Pre Auth (ASRepRoast)

## Technique Context

T1069.002 (Domain Groups) covers adversary enumeration of domain group memberships and related domain information to understand the target environment's structure and identify high-value targets. This specific test focuses on ASRepRoast reconnaissance — identifying domain users with the "Do not require Kerberos preauthentication" attribute set (userAccountControl flag UF_DONT_REQUIRE_PREAUTH). Users with this setting are vulnerable to ASRepRoasting attacks where attackers can request AS-REP responses without providing valid credentials, then crack the encrypted portion offline.

This technique is particularly valuable in the early stages of Active Directory attacks, as it identifies accounts that can be attacked without valid credentials. Detection engineers typically focus on PowerShell-based Active Directory enumeration commands, unusual LDAP queries, and the specific Get-ADUser cmdlet usage patterns that retrieve security-sensitive attributes.

## What This Dataset Contains

The core technique evidence appears in Security EID 4688 showing the PowerShell command execution: `"powershell.exe" & {get-aduser -f * -pr DoesNotRequirePreAuth | where {$_.DoesNotRequirePreAuth -eq $TRUE}}`. This command queries all domain users (`-f *`) with the DoesNotRequirePreAuth property and filters for those where this attribute equals TRUE.

PowerShell logging captures the specific scriptblock containing the ASRepRoast enumeration command: `{get-aduser -f * -pr DoesNotRequirePreAuth | where {$_.DoesNotRequirePreAuth -eq $TRUE}}` in EID 4104, along with the typical test framework boilerplate like Set-ExecutionPolicy Bypass and Set-StrictMode calls.

Sysmon provides the process creation chain showing powershell.exe (PID 42108) spawning a child powershell.exe (PID 43708) with the full command line visible. The parent process shows elevated privileges in Security EID 4703, including SeSecurityPrivilege and other high-level system privileges that would facilitate domain enumeration.

The process telemetry includes Sysmon EID 1 events for both the whoami.exe execution (system user discovery) and the primary PowerShell process executing the Get-ADUser command. Process access events (EID 10) show PowerShell accessing both the whoami.exe and child PowerShell processes with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

The dataset lacks the actual LDAP query traffic that Get-ADUser generates when communicating with domain controllers. There are no network connection events (Sysmon EID 3) showing the PowerShell process connecting to Active Directory services, which would be expected during domain enumeration operations.

Most importantly, the dataset contains no evidence of the command's success or failure — no output capture, no additional process spawning indicating successful enumeration, and no error messages suggesting the command was blocked. The technique appears to execute but we cannot determine if it successfully identified vulnerable accounts.

Authentication events like Kerberos ticket requests (Security EID 4768/4769) or LDAP bind operations that would accompany successful Active Directory queries are absent. The Security log also lacks any object access auditing (EID 4662) that might occur during directory queries, though this depends on specific audit policy configuration.

## Assessment

This dataset provides excellent visibility into the command execution mechanics of ASRepRoast user enumeration. The Security 4688 events with command-line logging capture the exact technique implementation, while PowerShell script block logging preserves the malicious cmdlet usage. The Sysmon process creation and process access events add valuable context about the execution chain and privileges involved.

However, the dataset is incomplete for understanding the full attack lifecycle. The absence of network telemetry and authentication events means analysts cannot determine if the enumeration succeeded, what accounts were discovered, or how the technique integrates with subsequent ASRepRoasting attacks. The data is strong for detecting the enumeration attempt but weak for assessing its impact or success.

## Detection Opportunities Present in This Data

1. **PowerShell Get-ADUser with DoesNotRequirePreAuth parameter** - Security EID 4688 command line containing "get-aduser" with "-pr DoesNotRequirePreAuth" parameters indicates ASRepRoast reconnaissance

2. **PowerShell script block logging for AD enumeration** - PowerShell EID 4104 containing "DoesNotRequirePreAuth" property queries combined with filtering operations targeting vulnerable accounts

3. **Process creation chain analysis** - Sysmon EID 1 showing powershell.exe spawning child PowerShell processes with Active Directory cmdlets in command lines

4. **Privilege escalation context** - Security EID 4703 showing PowerShell processes with high privileges (SeSecurityPrivilege, SeBackupPrivilege) preceding domain enumeration activities

5. **PowerShell execution policy bypass** - PowerShell EID 4103 showing Set-ExecutionPolicy with Bypass parameter as precursor to potentially malicious AD queries
