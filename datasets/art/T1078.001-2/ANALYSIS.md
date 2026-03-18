# T1078.001-2: Default Accounts — Activate Guest Account

## Technique Context

T1078.001 focuses on the abuse of default accounts—built-in user accounts that exist on all installations of an operating system. The Guest account is particularly significant as it's designed for temporary access but often disabled by default for security reasons. Attackers target this account because it typically has lower privileges but provides a foothold for persistence or lateral movement. When activated, the Guest account can be used for unauthorized access without creating new user accounts that might trigger detection.

The detection community focuses on monitoring account manipulation activities, particularly the enabling of traditionally disabled accounts like Guest. This technique sits at the intersection of multiple tactics—it can serve as initial access (if enabled remotely), persistence (maintaining access), defense evasion (using a "legitimate" account), and privilege escalation (if the account has unexpected permissions).

## What This Dataset Contains

This dataset captures a successful execution of guest account activation using the `net user guest /active:yes` command. The process chain shows:

1. **PowerShell test framework**: Process 29236 (`powershell.exe`) running as NT AUTHORITY\SYSTEM
2. **Command shell**: Process 21928 (`cmd.exe`) with command line `"cmd.exe" /c net user guest /active:yes`
3. **Net utilities**: Process 32028 (`net.exe`) followed by process 23948 (`net1.exe`) both executing `user guest /active:yes`

Security event 4688 captures all process creations with full command lines, including the critical command `"cmd.exe" /c net user guest /active:yes` and the subsequent `net user guest /active:yes` execution. Sysmon events provide additional process telemetry, with EID 1 events capturing the same process chain but with different rule classifications (T1087.001 for local account enumeration and T1018 for remote system discovery).

The PowerShell channel contains only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) rather than the actual technique execution, as the technique uses native Windows utilities rather than PowerShell cmdlets.

## What This Dataset Does Not Contain

This dataset lacks several key elements that would make detection more comprehensive. Most notably, it contains no account management events (Security EID 4720, 4722, 4724, 4738) that would directly show the guest account status change. The audit policy configuration shows account management logging is disabled (`account_management: none`), which explains this absence.

There are no logon events demonstrating actual use of the newly activated guest account—the dataset only captures the activation command, not subsequent authentication attempts. Additionally, there are no registry modifications that might be associated with account activation, and no Group Policy or local security policy change events that could provide additional context.

## Assessment

This dataset provides moderate utility for detection engineering focused on process-based detection of account manipulation. The Security 4688 events with command-line logging offer the strongest detection foundation, clearly capturing the `net user guest /active:yes` command execution. The Sysmon process creation events provide complementary telemetry with additional metadata like process GUIDs and parent-child relationships.

However, the dataset's value is significantly limited by the absence of account management audit events. In a production environment with proper account management logging enabled, the guest account activation would generate Security EID 4722 (user account enabled) events that provide direct evidence of the technique's success rather than just the attempt. The current dataset only shows process execution telemetry, which could potentially represent failed attempts.

For comprehensive detection of this technique, the dataset would be substantially stronger with account management logging enabled to capture the actual account state changes.

## Detection Opportunities Present in This Data

1. **Command-line pattern matching**: Security EID 4688 events containing `net user guest /active:yes` or similar account activation commands
2. **Process chain analysis**: Sysmon EID 1 events showing cmd.exe spawning net.exe with guest account manipulation parameters
3. **Suspicious parent-child relationships**: PowerShell or other scripting engines spawning cmd.exe with net user commands
4. **Account management utility execution**: Process creation of net.exe or net1.exe with user account modification flags (/active)
5. **Administrative context detection**: Process execution of account manipulation commands running under SYSTEM or other high-privilege contexts
6. **Command parameter analysis**: Parsing command-line arguments for guest account references combined with activation flags
7. **Process timing correlation**: Rapid succession of net.exe to net1.exe process creation indicating Windows user management workflow
