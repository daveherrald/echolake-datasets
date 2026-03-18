# T1112-43: Modify Registry — Disable Windows Error Reporting Settings

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where attackers modify Windows registry keys to alter system behavior, disable security controls, or maintain persistence. This specific test (T1112-43) targets Windows Error Reporting settings by creating registry values to disable enhanced notifications. Windows Error Reporting can provide telemetry about application crashes and system errors that might reveal attacker activity, making its disabling a common evasion tactic. The detection community focuses on monitoring registry modifications to security-relevant keys, particularly those that disable logging, monitoring, or security features.

## What This Dataset Contains

This dataset captures a PowerShell-initiated registry modification attack that attempts to disable Windows Defender's enhanced notifications. The core activity is visible in Security event 4688 showing cmd.exe execution with the command line: `"cmd.exe" /c reg add HKLM64\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting /v DisableEnhancedNotifications /t REG_DWORD /d 1 /f & reg add HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting /v DisableEnhancedNotifications /t REG_DWORD /d 1 /f`

Two reg.exe processes are captured in Sysmon event 1, with command lines targeting both the 64-bit and standard registry hives:
- `reg add HKLM64\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting /v DisableEnhancedNotifications /t REG_DWORD /d 1 /f`
- `reg add HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting /v DisableEnhancedNotifications /t REG_DWORD /d 1 /f`

Both reg.exe processes exit with status 0x1 (failure), indicating the registry modifications were unsuccessful. The process chain shows powershell.exe → cmd.exe → reg.exe, with PowerShell process access events (Sysmon EID 10) captured showing PROCESS_ALL_ACCESS (0x1FFFFF) to both child processes.

## What This Dataset Does Not Contain

This dataset lacks actual registry modification events. There are no Sysmon EID 13 (RegistryEvent - Value Set) or EID 12 (RegistryEvent - Object create and delete) events, indicating the registry changes were blocked or failed. The failure is confirmed by the reg.exe exit codes of 0x1. The dataset also doesn't contain any successful persistence artifacts or evidence of the registry values being created. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without the actual attack script content.

## Assessment

This dataset provides excellent telemetry for detecting attempted registry modifications to disable security features, even when the attempt fails. The process creation events with full command lines give clear indicators of malicious intent. The Security 4688 events with command-line auditing provide comprehensive coverage of the attack chain, while Sysmon adds valuable context with process GUIDs, hashes, and process access events. The failed execution actually makes this more realistic, as many real-world attacks fail due to insufficient privileges or security controls. However, the lack of successful registry modification events limits its utility for testing detections that specifically monitor for completed registry changes.

## Detection Opportunities Present in This Data

1. **Registry Modification Tool Execution** - Sysmon EID 1 and Security EID 4688 showing reg.exe execution with command lines containing "Windows Defender\Reporting" and "DisableEnhancedNotifications"

2. **Security Feature Tampering Command Lines** - Process creation events containing specific patterns like "DisableEnhancedNotifications", "Windows Defender", or registry paths targeting security policies

3. **Process Chain Analysis** - PowerShell spawning cmd.exe spawning reg.exe, indicating indirect execution of registry modification tools

4. **Bulk Registry Modification Attempts** - Multiple reg.exe processes with similar command lines targeting both 64-bit and standard registry hives in quick succession

5. **Process Access to Registry Tools** - Sysmon EID 10 showing PowerShell accessing reg.exe processes with PROCESS_ALL_ACCESS rights during registry modification attempts

6. **Failed Security Evasion Attempts** - Correlation of registry modification attempts with process exit codes indicating failure, suggesting blocked evasion techniques
