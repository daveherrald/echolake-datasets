# T1018-2: Remote System Discovery — Remote System Discovery - net group Domain Computers

## Technique Context

T1018 Remote System Discovery is a fundamental reconnaissance technique where attackers enumerate systems on the network to understand the target environment. The `net group "Domain Computers" /domain` command is a classic Windows discovery method that queries Active Directory to list all computer accounts in the domain. This technique is frequently used in the early stages of lateral movement planning, allowing attackers to identify potential targets for further exploitation. Detection engineers focus on monitoring net.exe executions with domain-related arguments, as these commands generate predictable process chains and often indicate reconnaissance activity.

## What This Dataset Contains

This dataset captures a clean execution of the net group domain enumeration technique. The Security channel shows the complete process chain in Security 4688 events: PowerShell (PID 248) spawning `cmd.exe /c net group "Domain Computers" /domain` (PID 1908), which then creates `net.exe group "Domain Computers" /domain` (PID 8144), followed by the actual worker process `net1.exe group "Domain Computers" /domain` (PID 4788). All processes execute successfully with exit status 0x0 in the corresponding 4689 termination events.

Sysmon provides complementary telemetry with ProcessCreate events (EID 1) for the key processes: whoami.exe (RuleName: technique_id=T1033), cmd.exe (RuleName: technique_id=T1087.001), net.exe (RuleName: technique_id=T1018), and net1.exe (RuleName: technique_id=T1018). The dataset also includes Sysmon ProcessAccess events (EID 10) showing PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF), indicating process monitoring or injection detection attempts.

The PowerShell channel contains only boilerplate test framework activity - Set-ExecutionPolicy Bypass commands and numerous Set-StrictMode scriptblocks with no actual technique-related PowerShell execution visible.

## What This Dataset Does Not Contain

The dataset lacks the actual output of the net group command - the list of domain computers that would normally be returned. This could indicate the command succeeded but the output wasn't captured in the telemetry, or that the domain query failed silently. There are no network-related events (DNS queries, LDAP connections) that would typically accompany domain enumeration, though these might be filtered by the Sysmon configuration. Additionally, there are no authentication events that might show the domain controller interaction required for this query to succeed.

## Assessment

This dataset provides excellent process execution telemetry for the T1018 technique through both Security 4688 command-line logging and Sysmon ProcessCreate events. The complete process chain from PowerShell through cmd.exe to net.exe/net1.exe is well-documented with full command lines, making it valuable for detection engineering. However, the lack of network telemetry and command output limits its utility for understanding the full impact of the technique. The Sysmon RuleName tagging correctly identifies the T1018 technique on the net.exe processes, demonstrating effective detection logic.

## Detection Opportunities Present in This Data

1. Monitor Security 4688 events for cmd.exe or PowerShell spawning net.exe with "Domain Computers" and "/domain" parameters in the command line
2. Create Sysmon ProcessCreate rules detecting net.exe executions with group enumeration arguments, particularly targeting domain-scoped queries
3. Alert on the characteristic net.exe → net1.exe parent-child process relationship when combined with domain group enumeration parameters
4. Correlate PowerShell ProcessAccess events (EID 10) with subsequent net.exe executions as potential indicators of automated reconnaissance scripts
5. Monitor for rapid sequential process creation patterns involving cmd.exe, net.exe, and net1.exe within short time windows
6. Detect process chains originating from system-level PowerShell (NT AUTHORITY\SYSTEM) that include domain enumeration commands
7. Create behavioral detection for processes accessing cmd.exe with full privileges (0x1FFFFF) followed immediately by net.exe domain queries
