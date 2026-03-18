# T1201-7: Password Policy Discovery — Examine domain password policy - Windows

## Technique Context

Password Policy Discovery (T1201) involves adversaries attempting to access detailed information about the password policy used by an organization. This intelligence is crucial for password spraying attacks, credential stuffing, and understanding account lockout thresholds before attempting brute-force attacks. The technique is commonly executed early in the discovery phase to inform subsequent credential-based attacks.

The specific test examined here uses `net accounts /domain` to query Active Directory domain password policy settings, which is a standard administrative command that returns information about minimum password length, password history, lockout thresholds, and other policy parameters. Detection teams focus on monitoring for unexpected execution of account enumeration commands, especially from non-administrative contexts or suspicious processes.

## What This Dataset Contains

This dataset captures a clean execution of domain password policy discovery via PowerShell. The Security channel shows the complete process execution chain in Security 4688 events: PowerShell (PID 9524) spawns `cmd.exe /c net accounts /domain` (PID 39864), which launches `net.exe accounts /domain` (PID 13896), which finally executes the actual `net1.exe accounts /domain` command (PID 21480). All processes execute successfully with exit status 0x0.

Sysmon provides complementary process creation telemetry with detailed command lines: `"cmd.exe" /c net accounts /domain` and the full process chain including `C:\Windows\system32\net1 accounts /domain`. The RuleName tags correctly identify these as T1059.003 (Windows Command Shell) and T1018 (Remote System Discovery) respectively, though T1201 would be more precise.

Sysmon EID 10 (Process Access) events show PowerShell accessing both the whoami.exe and cmd.exe processes with full access (0x1FFFFF), indicating normal parent-child process relationships rather than injection attempts.

The PowerShell channel contains only test framework boilerplate - Set-StrictMode scriptblocks and Set-ExecutionPolicy Bypass commands - with no evidence of the actual PowerShell commands that initiated the net accounts execution.

## What This Dataset Does Not Contain

The dataset lacks the actual PowerShell script content that triggered the net accounts command execution. The PowerShell 4104 events only show test framework initialization code, not the Invoke-Expression or similar commands that would have executed the discovery technique.

No network traffic is captured showing the LDAP queries that `net accounts /domain` would generate when connecting to domain controllers to retrieve password policy information. Similarly, there are no corresponding domain controller logs that would show the policy queries being serviced.

The output of the net accounts command is not captured in any log channel, so we cannot verify what password policy information was actually retrieved or whether the command succeeded in gathering domain policy details.

## Assessment

This dataset provides solid process-level telemetry for detecting the execution of domain password policy discovery commands. The Security 4688 events with command-line logging offer excellent detection coverage for the specific command used (`net accounts /domain`), while Sysmon adds process relationships and timing details.

However, the dataset has notable gaps for comprehensive detection engineering. The missing PowerShell script content limits understanding of how the technique was invoked, and the absence of network telemetry means detection rules cannot leverage LDAP query patterns or domain controller authentication logs that would provide additional detection angles.

For building detections focused on process execution patterns and command-line analysis, this dataset is quite strong. For developing network-based detections or understanding the complete attack flow including data exfiltration, additional telemetry sources would be valuable.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection** - Monitor Security 4688 events for processes executing `net accounts /domain`, `net accounts`, or similar account policy enumeration commands, especially when spawned from non-administrative tools like PowerShell or script interpreters.

2. **Process chain analysis** - Detect the specific execution pattern of PowerShell → cmd.exe → net.exe → net1.exe when the final command includes `/domain` parameter, indicating domain policy queries rather than local account management.

3. **Suspicious parent processes** - Alert on net.exe or net1.exe executions with domain-related parameters when the parent process is PowerShell, especially from non-standard working directories or under SYSTEM context outside of legitimate administrative tasks.

4. **Rapid successive process creation** - Monitor for quick sequential creation of cmd.exe, net.exe, and net1.exe processes within short time windows (under 1 second as seen here), which may indicate automated discovery scripts.

5. **Cross-reference with authentication logs** - Correlate these process execution events with domain controller authentication logs to identify which systems are querying password policies, enabling detection of unauthorized policy reconnaissance.
