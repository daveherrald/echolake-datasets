# T1069.002-9: Domain Groups — Enumerate Active Directory Groups with Get-AdGroup

## Technique Context

T1069.002 (Domain Groups) is a Discovery technique where adversaries enumerate domain-level security groups to understand organizational structure, identify high-privilege groups, and map potential lateral movement paths. The `Get-AdGroup` PowerShell cmdlet is a common tool for this enumeration, as it provides direct access to Active Directory group information when executed on domain-joined systems with appropriate privileges.

Detection engineers focus on PowerShell activity involving Active Directory cmdlets, command-line artifacts showing group enumeration patterns, and process creation events that indicate discovery behaviors. This technique often appears early in attack chains as adversaries gather intelligence about the target environment.

## What This Dataset Contains

This dataset captures a successful execution of `Get-AdGroup -Filter *` through PowerShell, generating comprehensive telemetry across multiple data sources:

**Primary execution evidence:**
- Security EID 4688 shows PowerShell process creation with command line: `"powershell.exe" & {Get-AdGroup -Filter *}`
- PowerShell EID 4104 script block logging captures the actual cmdlet execution: `{Get-AdGroup -Filter *}` and `& {Get-AdGroup -Filter *}`
- Sysmon EID 1 captures both the parent PowerShell process and the child PowerShell process executing the AD enumeration

**Supporting process activity:**
- Multiple Sysmon EID 7 events show .NET Framework and PowerShell assembly loading (mscorlib.ni.dll, System.Management.Automation.ni.dll, clr.dll)
- Sysmon EID 10 events capture process access between the parent and child PowerShell processes
- Sysmon EID 17 events show named pipe creation for PowerShell inter-process communication

**System context:**
- Security EID 4703 shows token privilege adjustment with multiple high-privilege rights enabled (SeBackupPrivilege, SeRestorePrivilege, etc.)
- Process termination events (Security EID 4689) document the cleanup of the enumeration activity

## What This Dataset Does Not Contain

The dataset lacks several key elements that would typically accompany successful AD group enumeration:

- **No network activity**: Missing DNS queries, LDAP connections, or Kerberos authentication events that would normally occur when querying Active Directory
- **No actual AD query results**: The PowerShell script block logs contain only the cmdlet invocation, not the enumerated group data
- **No module loading evidence**: Missing PowerShell EID 4103 events for ActiveDirectory module loading, suggesting the cmdlet may have failed to execute fully
- **Limited error handling**: No PowerShell error events or failure indicators that might explain incomplete execution

The absence of network telemetry and detailed AD interaction events suggests the enumeration attempt may have been blocked or failed due to insufficient privileges or connectivity issues, despite the process creation succeeding.

## Assessment

This dataset provides excellent coverage of the process creation and PowerShell execution aspects of domain group enumeration but falls short on capturing the actual Active Directory interaction. The Security audit logs with command-line logging and PowerShell script block logging provide strong detection opportunities for the technique attempt, even if the underlying AD query was unsuccessful.

The multiple data sources create overlapping coverage that's valuable for detection engineering, particularly the combination of Security 4688 events with full command lines and PowerShell 4104 script block logging. However, the lack of network telemetry limits the dataset's utility for understanding the complete attack flow.

## Detection Opportunities Present in This Data

1. **PowerShell AD cmdlet execution** - Monitor PowerShell EID 4104 script blocks containing `Get-AdGroup`, `Get-AdUser`, or other ActiveDirectory module cmdlets with wildcard filters

2. **Suspicious PowerShell command lines** - Alert on Security EID 4688 process creation events with PowerShell command lines containing AD enumeration patterns like `Get-AdGroup -Filter *`

3. **Privilege escalation indicators** - Monitor Security EID 4703 token adjustment events where multiple high-privilege rights are enabled in PowerShell contexts

4. **Process ancestry analysis** - Correlate parent-child PowerShell process relationships in Sysmon EID 1 events where child processes execute discovery commands

5. **PowerShell assembly loading patterns** - Monitor Sysmon EID 7 events for System.Management.Automation.ni.dll loading combined with subsequent AD-related PowerShell activity

6. **Named pipe communication** - Track Sysmon EID 17 PowerShell named pipe creation as an indicator of script execution that may precede discovery activities

7. **Process access monitoring** - Alert on Sysmon EID 10 events showing PowerShell processes accessing other PowerShell processes with high privileges (0x1FFFFF access rights)
