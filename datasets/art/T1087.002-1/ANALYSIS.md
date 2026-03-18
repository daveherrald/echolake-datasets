# T1087.002-1: Domain Account — Enumerate all accounts (Domain)

## Technique Context

T1087.002 Domain Account represents adversaries attempting to enumerate domain user accounts to understand the target environment and identify potential high-value targets. This technique is fundamental to Active Directory reconnaissance, allowing attackers to map user privileges, identify service accounts, and plan lateral movement or privilege escalation attacks. Detection teams focus heavily on this technique because it's both common in attack chains and generates distinctive telemetry through domain controller queries and built-in Windows utilities like `net user /domain` and `net group /domain`. The technique often appears early in the attack lifecycle during initial discovery phases.

## What This Dataset Contains

This dataset captures a successful execution of domain account enumeration using the classic `net user /domain` and `net group /domain` commands. The attack begins with PowerShell (process ID 26688) spawning cmd.exe with the command line `"cmd.exe" /c net user /domain & net group /domain`. Security event 4688 shows the complete process creation chain: powershell.exe → cmd.exe → net.exe → net1.exe, with each command properly logged.

The Sysmon data provides rich process creation details through event ID 1, capturing the net.exe execution with command line `net user /domain` (process ID 24276) and `net group /domain` (process ID 27540), followed by their respective net1.exe child processes (process IDs 20748 and 27680). The commands failed with exit status 0x1 in Security events 4689, likely due to domain connectivity issues in the test environment, but the attempt telemetry is fully captured.

Notable artifacts include Sysmon process access events (EID 10) showing PowerShell accessing both the cmd.exe and whoami.exe processes with full access rights (0x1FFFFF), and PowerShell script block logging capturing only framework boilerplate rather than the enumeration commands themselves.

## What This Dataset Does Not Contain

The dataset lacks the actual domain enumeration results since both net commands failed (exit code 0x1). There are no network connection events to domain controllers that would typically accompany successful domain queries, and no LDAP query telemetry. The PowerShell script block logs contain only Set-StrictMode boilerplate rather than the actual enumeration commands, indicating the technique was executed through cmd.exe rather than native PowerShell cmdlets like Get-ADUser. Additionally, there are no authentication events (4624/4625) or Kerberos ticket requests (4768/4769) that would normally accompany successful domain queries.

## Assessment

This dataset provides excellent visibility into the process execution patterns for domain account enumeration attempts, even when the underlying queries fail. The combination of Security 4688 events with full command-line logging and Sysmon EID 1 process creation events gives detection engineers comprehensive coverage of the attack's execution chain. The presence of both successful process creation telemetry and failure indicators (exit codes) makes this dataset particularly valuable for understanding how enumeration attempts appear regardless of success. The rich process genealogy (powershell → cmd → net → net1) is especially useful for building parent-child relationship detections.

## Detection Opportunities Present in This Data

1. **Net.exe domain enumeration pattern** - Security EID 4688 and Sysmon EID 1 showing net.exe with `/domain` parameter in command line
2. **Net command chaining** - Multiple net.exe executions in rapid succession with different `/domain` operations (user vs group enumeration)
3. **PowerShell spawning domain reconnaissance tools** - Process creation events showing powershell.exe as parent to cmd.exe executing domain enumeration
4. **Net.exe to net1.exe execution pattern** - Parent-child relationship between net.exe and net1.exe processes with domain parameters
5. **Command concatenation with enumeration intent** - cmd.exe command line containing multiple domain enumeration operations chained with `&`
6. **Process access patterns during enumeration** - Sysmon EID 10 showing PowerShell accessing enumeration processes with full rights (0x1FFFFF)
7. **Sequential domain discovery operations** - Time-correlated execution of user and group enumeration within seconds of each other
