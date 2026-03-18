# T1087.002-21: Domain Account — Suspicious LAPS Attributes Query with adfind all properties

## Technique Context

T1087.002 (Domain Account Discovery) involves adversaries enumerating domain user and computer accounts to understand the structure and composition of the target domain environment. This technique is fundamental to Active Directory reconnaissance, helping attackers identify high-value targets, understand domain trust relationships, and plan lateral movement. The specific test here uses AdFind.exe, a popular legitimate Active Directory query tool frequently abused by adversaries, to enumerate all computer objects with all attributes returned.

The detection community focuses heavily on monitoring for suspicious LDAP queries, especially those requesting all attributes (*) or targeting sensitive attributes like LAPS passwords, administrative group memberships, or service principal names. AdFind usage is particularly scrutinized because while legitimate for sysadmin work, it's heavily favored by ransomware groups and APTs for domain reconnaissance.

## What This Dataset Contains

The dataset captures a PowerShell-launched AdFind.exe execution attempting to enumerate domain computers with all attributes. Key telemetry includes:

**Process Creation Chain**: Security event 4688 shows PowerShell spawning a child PowerShell process with command line `"powershell.exe" & {& \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe\"  -h $env:USERDOMAIN -s subtree -f \"objectclass=computer\" *}`. Sysmon EID 1 captures the same process creation with ProcessGuid {9dc7570a-6369-69b4-eb3e-000000001000}.

**PowerShell Activity**: PowerShell channel events show the script block creation containing the AdFind command: `& {& "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe" -h $env:USERDOMAIN -s subtree -f "objectclass=computer" *}` (ScriptBlock ID 9c36a258-b664-4b4d-9c12-1883b9b0f506).

**Process Lifecycle**: Multiple Sysmon EID 7 events capture DLL loads for .NET runtime components and Windows Defender integration. Sysmon EID 10 shows process access events as PowerShell accesses child processes.

**System Discovery**: Sysmon EID 1 captures whoami.exe execution (ProcessGuid {9dc7570a-6368-69b4-ea3e-000000001000}) likely for privilege verification before domain enumeration.

## What This Dataset Does Not Contain

Notably absent is the actual AdFind.exe process creation event in Sysmon logs, despite the Security 4688 event showing PowerShell attempting to launch it. This suggests either the sysmon-modular configuration doesn't include AdFind.exe in its ProcessCreate include rules, or more likely, Windows Defender blocked the execution before AdFind could start.

The dataset lacks any network events (Sysmon EID 3) showing LDAP connections to domain controllers, which would normally be present during successful domain enumeration. There are no file creation events for AdFind output files, no DNS queries for domain controllers, and no LDAP bind or query telemetry that would indicate successful Active Directory communication.

The PowerShell logs contain only the script block creation but no execution completion events, error handling, or results processing, further suggesting the AdFind execution was blocked or failed.

## Assessment

This dataset provides excellent visibility into the preparation and attempt phase of domain enumeration but limited insight into successful execution. The combination of Security 4688 process auditing and PowerShell script block logging captures the full attack command line and intent. However, the absence of AdFind process telemetry and network activity significantly limits its utility for understanding complete attack chains.

The data is most valuable for detecting the setup and launch phases of domain enumeration attacks, particularly PowerShell-wrapped tool execution. It demonstrates how modern endpoint protection can truncate attack execution while still generating valuable forensic evidence of the attempt.

## Detection Opportunities Present in This Data

1. **AdFind Command Line Detection**: Monitor Security EID 4688 and Sysmon EID 1 for processes with command lines containing "adfind" or "AdFind.exe" combined with LDAP query parameters like "-f", "-h", and wildcard selectors (*).

2. **PowerShell Domain Enumeration**: Detect PowerShell EID 4104 script blocks containing Active Directory enumeration tools like AdFind, combined with LDAP filter syntax ("objectclass=computer", "objectclass=user") and attribute wildcards.

3. **Suspicious Process Ancestry**: Alert on PowerShell spawning external enumeration tools, especially when the command line includes domain-related parameters ($env:USERDOMAIN) and comprehensive attribute requests (*).

4. **Defender Intervention Patterns**: Monitor for process creation attempts that appear in Security logs but lack corresponding Sysmon ProcessCreate events, potentially indicating blocked execution attempts.

5. **Pre-Enumeration Reconnaissance**: Detect whoami.exe execution immediately preceding domain enumeration attempts, as adversaries often verify current privileges before conducting Active Directory queries.

6. **PowerShell Script Block Chaining**: Look for PowerShell script execution containing external tool invocation patterns, particularly when using invoke operators (&) to execute reconnaissance tools with domain-targeting parameters.
