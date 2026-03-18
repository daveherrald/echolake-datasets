# T1069.002-8: Domain Groups — Adfind - Query Active Directory Groups

## Technique Context

T1069.002 Domain Groups is a discovery technique where adversaries enumerate domain groups to understand the organizational structure and identify high-value targets. This technique is commonly observed in post-compromise reconnaissance phases, where attackers map domain privileges and group memberships to plan lateral movement or privilege escalation.

AdFind is a legitimate Active Directory query tool frequently abused by threat actors for domain enumeration. The community focuses detection efforts on AdFind execution patterns, its distinctive command-line arguments (particularly LDAP filters like `objectcategory=group`), and the comprehensive AD queries it enables. AdFind's popularity among ransomware groups and APTs makes it a high-priority detection target.

## What This Dataset Contains

This dataset captures a successful AdFind execution querying Active Directory groups. The key evidence appears in Security event 4688 showing the command line: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe" -f (objectcategory=group)`. 

The process chain shows PowerShell (PID 45004) spawning cmd.exe (PID 2152) which executes AdFind with the LDAP filter targeting group objects. Sysmon event 1 captures both the cmd.exe creation and a whoami.exe execution, indicating system reconnaissance activities. The cmd.exe process exits with status 0x1, suggesting AdFind encountered an error or completed with warnings.

PowerShell telemetry contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass), with no actual script content logged. Sysmon process access events (EID 10) show PowerShell accessing both whoami.exe and cmd.exe processes with full access rights (0x1FFFFF), indicating normal parent-child process relationships.

## What This Dataset Does Not Contain

The dataset lacks AdFind process creation events, indicating the sysmon-modular configuration doesn't include AdFind.exe in its process creation include rules. This is significant because AdFind execution telemetry would typically be the primary detection opportunity. The exit code 0x1 for cmd.exe suggests AdFind may have failed to execute successfully or encountered authentication/permission issues.

No network connections are logged, so we cannot observe LDAP queries to domain controllers. File creation events don't show AdFind output files, suggesting either the query failed or output was directed to stdout/stderr. Registry modifications and DNS queries related to AD enumeration are also absent.

## Assessment

This dataset provides limited detection value for AdFind-based domain group enumeration. While it captures the cmd.exe execution with the distinctive AdFind command line, the absence of AdFind process creation and the apparent execution failure significantly reduce its utility. The Security 4688 events provide the most valuable detection data, showing the complete command line with LDAP filter syntax.

The dataset would be stronger with successful AdFind execution, network telemetry showing LDAP queries, and potential output file creation. However, it still demonstrates how attackers invoke AdFind through command shells and provides examples of failed enumeration attempts that defenders should monitor.

## Detection Opportunities Present in This Data

1. Command line analysis in Security 4688 events for "AdFind.exe" execution with LDAP filters like "-f (objectcategory=group)"

2. Process creation patterns showing cmd.exe or PowerShell spawning external enumeration tools from non-standard directories

3. Suspicious parent-child relationships between PowerShell and cmd.exe executing reconnaissance tools

4. File path indicators pointing to "ExternalPayloads" or "AtomicRedTeam" directories suggesting test environments or staged tools

5. Process access patterns (Sysmon EID 10) showing scripting engines accessing spawned reconnaissance processes

6. Execution context analysis showing SYSTEM-level privileges used for domain enumeration activities

7. Sequential execution of identity discovery tools (whoami.exe) followed by domain enumeration attempts
