# T1069.002-3: Domain Groups — Elevated group enumeration using net group (Domain)

## Technique Context

T1069.002 (Domain Groups) is a fundamental discovery technique where attackers enumerate domain security groups to understand privilege structures and identify high-value targets. This technique is typically executed early in Active Directory reconnaissance phases to map out administrative hierarchies, backup operators, and other privileged groups. Detection engineers focus on monitoring native Windows tools like `net.exe` and `net1.exe` when used with `/domain` flags, as these commands require domain connectivity and often indicate lateral movement preparation. The detection community particularly watches for enumeration of well-known privileged groups like Domain Admins, Enterprise Admins, and backup-related groups, as these queries strongly suggest adversarial reconnaissance rather than legitimate administrative activity.

## What This Dataset Contains

This dataset captures a comprehensive execution of domain group enumeration using the native Windows `net` command. The technique executes through a PowerShell test framework that spawns `cmd.exe` with the command line: `"cmd.exe" /c net groups "Account Operators" /domain & net groups "Exchange Organization Management" /domain & net group "BUILTIN\Backup Operators" /domain & net group "Domain Admins" /domain`. 

Security event 4688 shows the full process chain: PowerShell → cmd.exe → net.exe → net1.exe for each group enumeration. The dataset includes attempts to query four distinct privileged groups, with varying exit codes indicating success/failure. Notably, net1.exe processes exit with status 0x2 for "Account Operators" and "Exchange Organization Management" (likely group not found errors), 0x1 for "BUILTIN\Backup Operators" (invalid parameter), and 0x0 for "Domain Admins" (success).

Sysmon captures the complete process creation chain with EID 1 events, including SHA256 hashes for net.exe (`AFBE51517092256504F797F6A5ABC02515A09D603E8C046AE31D7D7855568E91`) and net1.exe (`50E8AB76E511A917FD8CCF149DDAC1447FD817FF703AA9FDCC51DC77AC0237BE`). The Sysmon configuration correctly tags these as `technique_id=T1018,technique_name=Remote System Discovery`, though T1069.002 would be more precise for domain group enumeration.

## What This Dataset Does Not Contain

The dataset lacks network-level telemetry showing the actual LDAP queries to domain controllers, which would provide deeper insight into the enumeration mechanics. There are no Windows event logs from domain controllers (like 4624 logons or 4662 directory service access events) that would show the authentication and query patterns from the target perspective. 

The PowerShell channel contains only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) rather than the actual PowerShell commands that initiated the enumeration. Process access events (Sysmon EID 10) show PowerShell accessing spawned processes, but these represent normal parent-child process interactions rather than malicious process injection attempts.

The dataset also doesn't capture any potential output redirection or file creation beyond the standard PowerShell profile interactions, suggesting the enumeration results were displayed to console rather than logged to files.

## Assessment

This dataset provides excellent process-level telemetry for detecting domain group enumeration techniques. The Security channel's 4688 events with command-line logging deliver the primary detection value, clearly showing the net.exe invocations with `/domain` parameters targeting specific privileged groups. The Sysmon process creation events add valuable context with file hashes and parent-child relationships.

The combination of exit codes and targeted group names creates strong detection opportunities, as the specific groups queried (Domain Admins, Account Operators, etc.) are rarely accessed by legitimate users. The process chain visibility allows analysts to trace the enumeration back to the originating PowerShell session, enabling broader investigation of the attack sequence.

However, the dataset would be stronger with domain controller logs to show the server-side perspective and network captures to reveal the underlying LDAP queries and authentication patterns.

## Detection Opportunities Present in This Data

1. **Net.exe domain group enumeration** - Security EID 4688 showing `net.exe` or `net1.exe` with command lines containing `/domain` parameter and privileged group names like "Domain Admins", "Account Operators"

2. **Rapid sequential group queries** - Multiple net.exe process creations within short time windows (seconds) targeting different privileged groups, indicating systematic enumeration rather than single administrative queries

3. **PowerShell-initiated net command chains** - Process trees showing PowerShell as parent to cmd.exe, which spawns net.exe processes, particularly when combined with domain enumeration parameters

4. **Privileged group targeting patterns** - Command lines specifically referencing high-value groups like "Domain Admins", "Enterprise Admins", "BUILTIN\\Backup Operators", which are rarely queried by standard users

5. **Net.exe to net1.exe process pairs** - Sysmon EID 1 events showing the characteristic net.exe → net1.exe execution pattern with matching command lines, indicating native Windows network command usage

6. **Batch command execution for enumeration** - cmd.exe processes with command lines using `&` operators to chain multiple net group commands, suggesting automated or scripted reconnaissance activity
