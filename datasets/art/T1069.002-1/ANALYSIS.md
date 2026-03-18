# T1069.002-1: Domain Groups — Domain

## Technique Context

T1069.002 (Domain Groups) is a discovery technique where adversaries enumerate domain groups to understand the Active Directory structure and identify high-value targets. This is fundamental reconnaissance that attackers perform early in the attack lifecycle to map out privilege escalation paths and identify administrative accounts. The technique commonly uses built-in Windows utilities like `net group`, `net localgroup`, and Active Directory PowerShell modules.

Detection teams focus on identifying bulk enumeration activities, particularly when multiple group queries occur in rapid succession or when specific high-value groups like "Domain Admins" or "Enterprise Admins" are targeted. The technique often appears alongside other discovery activities as part of broader reconnaissance campaigns.

## What This Dataset Contains

This dataset captures a comprehensive domain group enumeration sequence executed via PowerShell and cmd.exe. The attack chain shows:

1. **PowerShell execution** (Process ID 1108) spawning child processes for enumeration
2. **Cmd.exe wrapper** with the command line: `"cmd.exe" /c net localgroup & net group /domain & net group "enterprise admins" /domain & net group "domain admins" /domain`
3. **Sequential net.exe executions** for each enumeration command:
   - `net localgroup` (Security EID 4688, Sysmon EID 1)
   - `net group /domain` with exit status 0x1 (failure, likely due to domain connectivity)
   - `net group "enterprise admins" /domain` (successful execution)
   - `net group "domain admins" /domain` (successful execution)

Each net.exe process spawns a corresponding net1.exe child process, showing the typical Windows behavior where net.exe acts as a dispatcher to net1.exe. The Sysmon data includes process creation events (EID 1) with full command lines, process access events (EID 10) showing PowerShell accessing child processes, and image load events (EID 7) capturing .NET framework loading for PowerShell execution.

The Security channel provides comprehensive process creation and termination logging (EIDs 4688/4689) with detailed command lines, while PowerShell logging contains only test framework boilerplate (Set-ExecutionPolicy Bypass).

## What This Dataset Does Not Contain

The dataset lacks the actual enumeration output - we see the process executions but not the group membership information returned by the commands. The `net group /domain` command failed (exit status 0x1), suggesting potential domain connectivity issues during testing. 

There are no network connection events that would typically accompany domain queries, and no LDAP-related events that might occur during Active Directory enumeration. The dataset also lacks any Windows Security events related to directory service access (EID 4662) that might occur during legitimate domain group queries.

## Assessment

This dataset provides excellent telemetry for detecting domain group enumeration through native Windows utilities. The combination of Security EID 4688 events with full command-line logging and Sysmon EID 1 events creates robust detection opportunities. The process tree relationship between PowerShell → cmd.exe → net.exe → net1.exe is clearly visible across both data sources.

The presence of both successful and failed enumeration attempts adds realistic context, as domain connectivity issues are common in real environments. The timing correlation between process creation and termination events allows for precise reconstruction of the attack sequence.

## Detection Opportunities Present in This Data

1. **Bulk group enumeration detection**: Multiple net.exe processes with group-related commands within a short time window (4 processes in ~100ms)

2. **High-value group targeting**: Specific queries for "enterprise admins" and "domain admins" groups in command lines

3. **Process chain analysis**: PowerShell spawning cmd.exe spawning multiple net.exe processes in rapid succession

4. **Command-line pattern matching**: The characteristic `/domain` parameter combined with group names in net.exe command lines

5. **Parent-child process relationships**: Unusual PowerShell → cmd.exe → net.exe process ancestry that deviates from typical administrative workflows

6. **Enumeration failure patterns**: Detection of failed domain queries (exit status 0x1) that might indicate reconnaissance attempts in environments with network restrictions

7. **PowerShell process access events**: Sysmon EID 10 events showing PowerShell accessing spawned enumeration processes with high privileges (0x1FFFFF access)
