# T1222.001-2: Windows File and Directory Permissions Modification — cacls - Grant permission to specified user or group recursively

## Technique Context

T1222.001 involves modifying file and directory permissions on Windows systems to evade defenses, often by granting broader access to files that would normally be restricted. Attackers use this technique to maintain persistence, escalate privileges, or access sensitive data by modifying ACLs through tools like `icacls`, `cacls`, `takeown`, or `attrib`. The detection community focuses on monitoring permission modification commands, especially those targeting system directories, executable files, or security-relevant locations. Key detection opportunities include process creation events for permission-modifying utilities, command-line analysis for suspicious permission grants (especially to "Everyone" or overly permissive rights), and file access patterns following permission changes.

## What This Dataset Contains

This dataset captures a PowerShell-initiated file permission modification using `icacls.exe`. The process chain shows PowerShell (PID 7516) spawning `cmd.exe` with the command `"cmd.exe" /c icacls.exe %temp%\T1222.001_cacls /grant Everyone:F`, which then executes `icacls.exe C:\Windows\TEMP\T1222.001_cacls /grant Everyone:F`. 

Security event 4688 captures the full command line: `icacls.exe  C:\Windows\TEMP\T1222.001_cacls /grant Everyone:F`, showing the attempt to grant Full Control (`F`) permissions to the Everyone group on a test file in the temp directory. Sysmon event 1 provides additional context with the complete process creation details, including hashes and parent process information.

The dataset shows the technique failing - both `cmd.exe` and `icacls.exe` exit with status `0x2` (file not found), indicating the target file `T1222.001_cacls` doesn't exist in the temp directory. However, the telemetry still captures the malicious intent through the command-line arguments.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful permission modification since the target file doesn't exist. There are no object access audit events (4670) that would show actual ACL changes, no subsequent file access attempts using the modified permissions, and no defensive alerts from Windows Defender despite the technique attempt. The sysmon-modular configuration filtered out some process creation events - only `whoami.exe`, `cmd.exe`, and `icacls.exe` appear in Sysmon EID 1 events because they match the include-mode filtering patterns for known suspicious utilities.

## Assessment

This dataset provides excellent telemetry for detecting file permission modification attempts through the command-line logging in both Security 4688 and Sysmon 1 events. The complete process chain from PowerShell → cmd.exe → icacls.exe is well-documented with full command lines, making it ideal for building detections around suspicious `icacls` usage patterns. While the technique failed execution-wise, the command-line evidence clearly shows malicious intent to grant excessive permissions to the Everyone group. The exit status information in Security 4689 events adds valuable context for distinguishing between successful and failed attempts.

## Detection Opportunities Present in This Data

1. **Command-line detection for icacls permission grants** - Monitor Security 4688 and Sysmon 1 events for `icacls.exe` with `/grant` parameter, especially grants to "Everyone" or overly permissive rights like `:F` (Full Control)

2. **PowerShell spawning permission modification tools** - Alert on PowerShell processes creating child processes of `icacls.exe`, `cacls.exe`, or `takeown.exe` with permission-modifying arguments

3. **Suspicious permission grant patterns** - Detect icacls commands granting Full Control (`:F`) or Modify (`:M`) permissions to broad groups like "Everyone", "Users", or "Authenticated Users"

4. **Process chain analysis** - Monitor for cmd.exe being used as an intermediary to execute permission modification commands, especially when spawned by scripting engines

5. **Exit status correlation** - Correlate Security 4688 process creation events with 4689 exit events to identify failed permission modification attempts (exit status 0x2) that may indicate reconnaissance or testing

6. **Temp directory targeting** - Flag icacls operations targeting files in `%temp%`, `%appdata%`, or other user-writable locations that could indicate staging for persistence mechanisms
