# T1047-6: Windows Management Instrumentation — WMI Execute Remote Process

## Technique Context

T1047 (Windows Management Instrumentation) is a versatile execution technique that leverages WMI's built-in remote administration capabilities to execute processes on local or remote systems. Attackers commonly use WMI for lateral movement, persistence, and remote code execution because it operates over existing administrative protocols and appears as legitimate system activity. The technique is particularly valuable for bypassing application whitelisting and executing commands without dropping files to disk.

Detection engineers focus on WMI process creation events, command-line analysis for WMI utilities (wmic.exe, PowerShell WMI cmdlets), and network connections to WMI services. The community emphasizes monitoring for suspicious WMI queries, process creation via WMI, and authentication events associated with WMI remote connections.

## What This Dataset Contains

This dataset captures a WMI remote process execution attempt using the deprecated wmic.exe utility. The attack chain begins with PowerShell (PID 34024) spawning cmd.exe with the command `"cmd.exe" /c wmic /user:DOMAIN\Administrator /password:P@ssw0rd1 /node:"127.0.0.1" process call create notepad.exe`. Security event 4688 shows cmd.exe (PID 33644) then executing `wmic /user:DOMAIN\Administrator /password:P@ssw0rd1 /node:"127.0.0.1" process call create notepad.exe`.

Sysmon captures the complete process chain: PowerShell → cmd.exe → wmic.exe (PID 34256). The wmic.exe process loads several WMI-related DLLs including wmiutils.dll (EID 7), confirming WMI functionality engagement. Security event 4703 shows wmic.exe acquiring extensive privileges including SeAssignPrimaryTokenPrivilege and SeBackupPrivilege.

Critically, both cmd.exe and wmic.exe exit with error status 0x80041064 (Security events 4689), indicating the WMI operation failed. This error code corresponds to WBEM_E_INVALID_PARAMETER or authentication failure, suggesting the provided credentials were invalid or the target system rejected the connection.

## What This Dataset Does Not Contain

The dataset lacks successful remote process creation evidence because the WMI operation failed with authentication errors. There are no Sysmon ProcessCreate events for notepad.exe on the target system, no WMI service activity logs, and no successful authentication events that would indicate credential validation. Network connection events (Sysmon EID 3) are absent, likely because the connection attempt failed before establishing a network session.

The PowerShell telemetry contains only test framework boilerplate (Set-ExecutionPolicy Bypass commands) rather than the actual WMI execution commands, indicating the test framework used cmd.exe as an intermediary rather than direct PowerShell WMI cmdlets.

## Assessment

This dataset provides excellent telemetry for detecting attempted WMI remote execution, even when the attack fails. The Security channel captures the complete command-line with embedded credentials, process creation chain, and privilege escalation attempts. Sysmon enriches this with process GUIDs, image loads, and file hashes. The combination offers multiple detection points for both successful and failed WMI attacks.

The failure scenario is particularly valuable because it represents common real-world conditions where attackers use incorrect credentials or target unreachable systems. The error codes and exit statuses provide clear indicators of failure modes that defenders can use to identify reconnaissance attempts or credential spraying.

## Detection Opportunities Present in This Data

1. **Command-line credential exposure** - Security EID 4688 contains plaintext credentials in wmic.exe command line: `/user:DOMAIN\Administrator /password:P@ssw0rd1`

2. **WMI utility execution with remote parameters** - Process creation of wmic.exe with `/node:` parameter and `process call create` syntax indicating remote execution attempt

3. **Privilege escalation patterns** - Security EID 4703 shows wmic.exe acquiring 12 high-privilege rights including SeAssignPrimaryTokenPrivilege and SeBackupPrivilege

4. **Process chain analysis** - Sysmon events show suspicious parent-child relationships: powershell.exe → cmd.exe → wmic.exe for command execution obfuscation

5. **WMI library loading** - Sysmon EID 7 captures wmiutils.dll loading into wmic.exe process, indicating WMI functionality activation

6. **Failed execution indicators** - Security EID 4689 exit codes 0x80041064 on both cmd.exe and wmic.exe processes indicate authentication or parameter failures

7. **Localhost targeting patterns** - Command line shows `/node:"127.0.0.1"` which may indicate lateral movement testing or local privilege escalation attempts
