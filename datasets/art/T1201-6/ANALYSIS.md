# T1201-6: Password Policy Discovery — Examine local password policy - Windows

## Technique Context

T1201 Password Policy Discovery is a common discovery technique where attackers enumerate password policies to understand security controls and plan credential-based attacks. The `net accounts` command is a fundamental Windows administrative tool that reveals local password policy settings including minimum password length, password history, lockout thresholds, and maximum password age. This information helps attackers understand password complexity requirements for brute force attacks, identify weak policy configurations, and plan credential stuffing campaigns. Detection engineers focus on monitoring native Windows utilities like `net.exe` and `net1.exe` when used with account-related parameters, as these are frequently leveraged by both legitimate administrators and adversaries during reconnaissance phases.

## What This Dataset Contains

This dataset captures a complete execution of `net accounts` through PowerShell. The Security channel shows the full process chain in Security event 4688 logs: PowerShell (PID 42636) spawning `cmd.exe /c net accounts` (PID 25560), which then launches `net.exe accounts` (PID 35420), followed by the actual worker process `net1.exe accounts` (PID 19688). All processes exit cleanly with status 0x0 as shown in Security 4689 events.

The Sysmon data provides complementary process creation telemetry through EID 1 events, capturing the same process chain with full command lines: `"cmd.exe" /c net accounts`, `net accounts`, and `C:\Windows\system32\net1 accounts`. The Sysmon ProcessCreate events are tagged with relevant MITRE techniques (T1059.003 for cmd.exe, T1018 for net.exe/net1.exe). Sysmon EID 10 events show PowerShell accessing both the whoami.exe and cmd.exe processes with full access rights (0x1FFFFF).

The PowerShell channel contains only framework boilerplate (Set-ExecutionPolicy Bypass) with no script block logging of the actual `net accounts` execution, indicating the command was run directly rather than through PowerShell cmdlets.

## What This Dataset Does Not Contain

This dataset lacks the actual output of the `net accounts` command - there are no artifacts showing the password policy information that would be displayed to the user. The technique executed successfully (all processes exit with code 0x0) but the policy enumeration results are not captured in the Windows event logs. Additionally, there are no network connections, registry modifications, or file system artifacts beyond PowerShell profile creation, as this is purely a local information gathering command that reads from the Security Accounts Manager (SAM) database.

## Assessment

This dataset provides excellent telemetry for detecting the execution of `net accounts` through the complete process lineage captured in both Security 4688 and Sysmon EID 1 events. The command-line logging clearly shows the password policy discovery intent, and the process relationships are well-documented. However, the dataset's value is limited by the lack of output capture - defenders cannot see what password policy information was actually disclosed to the attacker. For building detections focused on the execution behavior rather than the information disclosure impact, this data is highly valuable.

## Detection Opportunities Present in This Data

1. **Net.exe Account Enumeration Detection** - Monitor Security 4688 or Sysmon EID 1 for `net.exe` or `net1.exe` processes with command lines containing "accounts" parameter to detect password policy discovery attempts.

2. **Suspicious Process Chain Analysis** - Detect unusual parent processes (like PowerShell) spawning cmd.exe with net accounts commands, indicating potential scripted reconnaissance activity.

3. **Multiple Discovery Technique Correlation** - Combine this net accounts execution with the whoami.exe execution (EID 1 with T1033 tag) to identify broader system discovery activities within the same PowerShell session.

4. **Command Shell Spawning from PowerShell** - Alert on PowerShell processes creating cmd.exe children processes as captured in Sysmon EID 1 events, which often indicates living-off-the-land technique usage.

5. **Process Access Pattern Detection** - Monitor Sysmon EID 10 events showing PowerShell accessing system utilities with full access rights (0x1FFFFF), which may indicate process injection preparation or monitoring behavior.
