# T1112-31: Modify Registry — Windows HideSCAVolume Group Policy Feature

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries alter Windows registry keys to hide their activities, maintain persistence, or change system behavior. The HideSCAVolume feature specifically controls the visibility of System Configuration Analyzer (SCA) volumes in Windows Explorer. When set to 1, this registry value hides certain system volumes from being displayed to users, potentially concealing malicious activity or files stored on those volumes. Attackers use registry modification as a low-noise method to alter system behavior without requiring additional tools beyond native Windows utilities. Detection engineering typically focuses on monitoring for reg.exe usage, PowerShell registry cmdlets, and direct registry API calls targeting sensitive keys.

## What This Dataset Contains

This dataset captures a straightforward registry modification executed via PowerShell spawning cmd.exe and reg.exe. The process chain shows PowerShell (PID 39764) executing `cmd.exe /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAVolume /t REG_DWORD /d 1 /f` followed by reg.exe (PID 44024) with the same command line parameters.

Key evidence includes:
- Sysmon EID 1 captures the cmd.exe process creation: `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAVolume /t REG_DWORD /d 1 /f`
- Sysmon EID 1 captures reg.exe process creation with the full registry modification command
- Security EID 4688 events provide parallel process creation telemetry with command lines
- Process access events (Sysmon EID 10) show PowerShell accessing both child processes with PROCESS_ALL_ACCESS (0x1FFFFF)
- All processes execute successfully with exit status 0x0

The command targets the Explorer Policies registry location under HKEY_CURRENT_USER, setting HideSCAVolume to 1 with forced overwrite (/f flag).

## What This Dataset Does Not Contain

The dataset lacks the actual registry modification event itself - there are no Sysmon EID 12/13/14 (Registry object added/value set/key and value renamed) events because the sysmon-modular configuration doesn't monitor this specific registry path. Windows doesn't generate Security audit events for registry changes by default since object access auditing is disabled in this environment. The PowerShell channel contains only test framework boilerplate (Set-ExecutionPolicy Bypass, Set-StrictMode) rather than the actual registry modification commands. No Windows Defender alerts appear, indicating this technique completed without triggering behavioral detection.

## Assessment

This dataset provides good coverage for process-based detection of registry modification techniques. While it lacks direct registry monitoring telemetry, the process creation events with full command lines offer robust detection opportunities. The Security and Sysmon channels complement each other well, with Security providing guaranteed process coverage and Sysmon adding process access context. The clean execution with clear parent-child relationships and complete command lines makes this excellent data for building process-based detections. Adding registry monitoring via Sysmon configuration updates would strengthen coverage significantly.

## Detection Opportunities Present in This Data

1. **reg.exe execution with Explorer Policies path** - Monitor Sysmon EID 1 or Security EID 4688 for reg.exe processes with command lines containing "Policies\Explorer" and "HideSCAVolume"

2. **cmd.exe spawning reg.exe for registry modification** - Detect cmd.exe parent processes executing reg.exe children with "add" operations

3. **PowerShell spawning cmd.exe for indirect registry access** - Monitor for PowerShell processes creating cmd.exe children with registry modification commands

4. **Process access to registry utilities** - Alert on processes accessing reg.exe with PROCESS_ALL_ACCESS rights, especially from scripting engines

5. **Registry key targeting user policies** - Flag reg.exe operations targeting HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies paths

6. **Forced registry overwrites** - Detect reg.exe executions using the /f (force) flag combined with sensitive registry locations

7. **System-context registry modification** - Monitor for SYSTEM account executing registry changes to user policy locations, which may indicate privilege escalation or persistence
