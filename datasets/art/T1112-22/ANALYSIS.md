# T1112-22: Modify Registry — Activate Windows NoFileMenu Group Policy Feature

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries alter Windows registry values to disable security features, hide malicious activity, or establish persistence mechanisms. The registry serves as Windows' central configuration database, making it a prime target for attackers seeking to modify system behavior without requiring file system changes.

This specific test activates the Windows NoFileMenu Group Policy feature by setting `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoFileMenu` to 1. This registry modification disables the File menu in Windows Explorer, demonstrating how adversaries might use Group Policy-related registry keys to restrict user functionality or hide evidence of their activities. Detection engineers typically focus on monitoring registry modifications to sensitive keys, particularly those related to security policies, startup locations, and system configurations.

## What This Dataset Contains

This dataset captures a straightforward registry modification attack executed via PowerShell and reg.exe. The primary attack evidence appears in Security event 4688, showing the command execution: `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoFileMenu /t REG_DWORD /d 1 /f` followed by the actual reg.exe execution with command line `reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoFileMenu /t REG_DWORD /d 1 /f`.

The process execution chain is clearly visible: PowerShell (PID 29552) spawns cmd.exe (PID 37496), which then spawns reg.exe (PID 30208). Sysmon provides complementary coverage with EID 1 events showing the same process creations with additional context like process GUIDs, hashes, and parent-child relationships. Security events 4689 document clean process terminations with exit status 0x0, indicating successful execution.

The PowerShell channel contains only test framework boilerplate—Set-StrictMode scriptblocks and Set-ExecutionPolicy Bypass commands typical of the Atomic Red Team test framework, with no evidence of the actual registry modification commands being logged at the PowerShell level.

## What This Dataset Does Not Contain

Notably absent from this dataset are Sysmon EID 13 (Registry value set) events, which would directly capture the registry modification itself. The sysmon-modular configuration appears to filter out routine registry changes, focusing instead on process-level telemetry. Additionally, there are no Sysmon EID 12 (Registry object added or deleted) or EID 14 (Registry key and value renamed) events that might provide additional registry monitoring coverage.

The dataset lacks any evidence of Windows Defender intervention—all processes complete successfully with normal exit codes, indicating the registry modification technique was not blocked by the endpoint protection solution. There's also no Application event log data that might capture Group Policy processing or policy enforcement activities related to the NoFileMenu setting.

## Assessment

This dataset provides solid process-level telemetry for detecting registry modification attacks but lacks direct registry monitoring evidence. The Security audit logs with command-line logging offer excellent visibility into the attack technique, clearly showing both the command execution method and the specific registry target. Sysmon's process creation events add valuable enrichment with hashes, parent-child relationships, and detailed command lines.

However, the absence of direct registry monitoring (Sysmon EID 13) limits the dataset's value for building registry-focused detections. Detection engineers would need to rely on process and command-line analysis rather than direct registry change monitoring. This reflects a common real-world scenario where process monitoring is more readily available than comprehensive registry auditing.

## Detection Opportunities Present in This Data

1. **Registry modification via reg.exe** - Security EID 4688 and Sysmon EID 1 showing reg.exe execution with HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer target path and NoFileMenu value name

2. **Command-line obfuscation patterns** - cmd.exe spawning with `/c` parameter to execute registry commands, indicating potential process laundering through cmd.exe

3. **Group Policy registry tampering** - Process command lines targeting the Policies\Explorer registry path, which contains Group Policy enforcement settings

4. **PowerShell-initiated registry modifications** - Process tree analysis showing PowerShell as the ultimate parent of registry modification tools

5. **Suspicious registry tool usage** - reg.exe execution with add operations targeting user policy locations, particularly when originating from scripting environments

6. **Process access anomalies** - Sysmon EID 10 showing PowerShell accessing spawned processes (whoami.exe, cmd.exe) with full access rights (0x1FFFFF), indicating potential process monitoring or manipulation
