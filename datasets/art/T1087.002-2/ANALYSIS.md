# T1087.002-2: Domain Account — Enumerate all accounts via PowerShell (Domain)

## Technique Context

T1087.002 (Account Discovery: Domain Account) involves adversaries enumerating domain user accounts to understand the domain structure and identify high-value targets. This technique is fundamental to Active Directory reconnaissance and is commonly observed in both penetration testing and real-world attacks. Attackers use various methods including built-in Windows commands (`net user /domain`), PowerShell cmdlets (`Get-ADUser`), and LDAP queries to discover domain accounts, group memberships, and organizational structure.

The detection community focuses on identifying enumeration patterns through process creation telemetry, command-line arguments containing domain discovery keywords, and unusual PowerShell activity involving Active Directory modules. This technique often appears early in the attack lifecycle during the discovery phase and can indicate lateral movement preparation.

## What This Dataset Contains

This dataset captures a comprehensive PowerShell-based domain enumeration execution with the following key artifacts:

**Process Chain**: The execution creates three distinct enumeration processes:
- Security 4688 shows PowerShell spawning `"powershell.exe" & {net user /domain; get-localgroupmember -group Users; get-aduser -filter *}`
- Sysmon EID 1 captures `"C:\Windows\system32\net.exe" user /domain` (PID 27404)
- Sysmon EID 1 shows the subsequent `net1.exe` execution with `C:\Windows\system32\net1 user /domain` (PID 30132)

**PowerShell Activity**: 
- Security 4688 events show the main PowerShell process with full command line: `"powershell.exe" & {net user /domain; get-localgroupmember -group Users; get-aduser -filter *}`
- PowerShell 4104 events capture script blocks for `Get-LocalGroupMember` execution
- PowerShell 4103 shows `Get-LocalGroupMember -group Users` command invocation

**Process Outcomes**: Security 4689 events show both `net.exe` and `net1.exe` exiting with status `0x1`, indicating the domain enumeration commands likely failed (expected in an isolated test environment).

**Sysmon Detection Artifacts**: Multiple Sysmon EID 1 events with technique-specific RuleNames including `technique_id=T1087.001,technique_name=Local Account` and `technique_id=T1018,technique_name=Remote System Discovery`.

## What This Dataset Does Not Contain

**Missing Network Activity**: No Sysmon EID 3 (NetworkConnect) events are present, likely because the domain queries failed before establishing LDAP connections to domain controllers.

**No Active Directory Query Results**: The PowerShell `get-aduser -filter *` command appears to have failed silently, producing no additional telemetry beyond the initial script block creation.

**Limited PowerShell Evidence**: While script blocks are captured for execution setup, the actual enumeration output and any potential AD module loading are not visible in the telemetry.

**No Domain Controller Communication**: Expected DNS queries (Sysmon EID 22) or Kerberos authentication attempts that would typically accompany successful domain enumeration are absent.

## Assessment

This dataset provides solid detection opportunities for PowerShell-based domain enumeration attempts, even when the techniques fail to complete successfully. The combination of Security 4688 command-line logging and Sysmon process creation events creates multiple detection layers. The presence of both traditional Windows commands (`net user /domain`) and PowerShell cmdlets (`Get-ADUser`) in a single execution makes this particularly valuable for testing detection logic that identifies enumeration tool combinations.

The process access events (Sysmon EID 10) showing PowerShell accessing child processes also provide behavioral indicators that could supplement command-line based detections. However, the lack of successful domain communication limits the dataset's utility for testing network-based detection approaches.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection** on Security 4688 events for `net user /domain` execution and PowerShell scripts containing AD enumeration cmdlets

2. **PowerShell script block analysis** using PowerShell 4104 events to identify `Get-LocalGroupMember` and `Get-ADUser` cmdlet usage in script blocks

3. **Process chain analysis** detecting PowerShell spawning `net.exe` followed by `net1.exe` for domain user enumeration

4. **Sysmon rule-based alerting** leveraging the technique-tagged process creation events (T1087.001, T1018) for immediate identification

5. **Multi-tool enumeration detection** identifying the combination of built-in Windows tools (`net.exe`) and PowerShell Active Directory cmdlets within the same execution context

6. **PowerShell command invocation monitoring** through PowerShell 4103 events showing direct cmdlet execution with group enumeration parameters

7. **Process access pattern analysis** using Sysmon EID 10 events to identify PowerShell accessing enumeration tool child processes with full access rights (0x1FFFFF)
