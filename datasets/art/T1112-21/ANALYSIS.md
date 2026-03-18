# T1112-21: Modify Registry — Activate Windows NoControlPanel Group Policy Feature

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries modify Windows registry keys to hide malicious activity, disable security features, or establish persistence. This specific test activates the NoControlPanel Group Policy feature by creating a registry entry that prevents users from accessing the Windows Control Panel. While seemingly simple, registry modifications like this are commonly used by malware to restrict system administration capabilities, making incident response and remediation more difficult. The detection community focuses on monitoring registry modifications to security-relevant keys, especially those affecting system policies, Windows Defender settings, and administrative controls.

## What This Dataset Contains

This dataset captures the complete execution chain of the NoControlPanel registry modification technique. The Security event log shows the full process lineage in 4688 events: PowerShell (`0x6fac`) spawning cmd.exe (`0x6098`) with command line `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoControlPanel /t REG_DWORD /d 1 /f`, which then spawns reg.exe (`0x5df0`) with the actual registry modification command `reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoControlPanel /t REG_DWORD /d 1 /f`.

Sysmon provides complementary process creation events (EID 1) for cmd.exe and reg.exe with full command lines, along with process access events (EID 10) showing PowerShell accessing both child processes with PROCESS_ALL_ACCESS (0x1FFFFF) permissions. The Sysmon events include detailed process ancestry, file hashes, and integrity levels, all running as NT AUTHORITY\SYSTEM.

The PowerShell channel contains only standard test framework boilerplate (Set-ExecutionPolicy and various error handling scriptblocks) with no evidence of the actual technique execution, indicating this was likely executed via PowerShell's Start-Process or similar process creation rather than direct PowerShell commands.

## What This Dataset Does Not Contain

Critically, this dataset lacks the actual registry modification telemetry. There are no Sysmon EID 13 (Registry value set) events, which would normally capture the creation of the `NoControlPanel` value in `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`. This absence suggests the sysmon-modular configuration may not be configured to monitor this specific registry location, or the registry modification failed to execute successfully despite the process creation succeeding (reg.exe exited with status 0x0, indicating success).

The dataset also lacks any Windows Defender alerts or blocking events, suggesting this registry modification was not flagged as malicious behavior by the endpoint protection system.

## Assessment

This dataset provides excellent process execution telemetry for detecting the technique through command-line analysis and process chain monitoring, but falls short on capturing the actual registry modification that constitutes the technique's core impact. The Security and Sysmon process creation events contain rich detection opportunities through command-line patterns and parent-child process relationships. However, without registry modification events, defenders cannot confirm the technique actually succeeded in modifying the target registry key.

For detection engineering focused on process-based indicators, this dataset is highly valuable. For registry-focused detections or incident response validation of system state changes, additional registry monitoring would be required.

## Detection Opportunities Present in This Data

1. **Command-line pattern matching** - Security EID 4688 and Sysmon EID 1 capture the distinctive `reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoControlPanel` command pattern

2. **Process chain analysis** - Detect PowerShell spawning cmd.exe spawning reg.exe, especially when cmd.exe uses `/c` parameter for single command execution

3. **Registry tool abuse** - Monitor reg.exe execution with `add` operations targeting policy-related registry paths, particularly those containing "Policies\Explorer"

4. **LOLBin execution context** - Alert on reg.exe execution from non-administrative contexts or unusual parent processes like PowerShell scripts

5. **Process access patterns** - Sysmon EID 10 events show PowerShell accessing child processes with full access rights (0x1FFFFF), indicating potential process injection preparation or monitoring

6. **System integrity impact** - Monitor registry modifications targeting `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` with any value names related to system restrictions (NoControlPanel, NoRun, NoClose, etc.)
