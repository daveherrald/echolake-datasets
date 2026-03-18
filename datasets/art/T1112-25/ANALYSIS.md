# T1112-25: Modify Registry — Activate Windows NoTrayContextMenu Group Policy Feature

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries alter Windows registry keys to disable security controls, establish persistence, or modify system behavior. The detection community focuses heavily on monitoring registry modifications to sensitive keys like those controlling security policies, Windows Defender settings, authentication mechanisms, and Group Policy configurations.

This specific test activates the Windows NoTrayContextMenu Group Policy feature by setting `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoTrayContextMenu` to 1. While this particular modification only disables the system tray context menu (a minor UI restriction), adversaries commonly target the `Policies\Explorer` registry path to disable security features like Windows Defender, UAC prompts, or system restore functionality.

## What This Dataset Contains

The dataset captures a clean execution of the registry modification technique through the following process chain:

**Process Execution Chain:**
- PowerShell (PID 8308) → cmd.exe (PID 20340) → reg.exe (PID 33620)
- Security 4688 events show the complete command lines: `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoTrayContextMenu /t REG_DWORD /d 1 /f`

**Sysmon Process Creation:**
- EID 1 captures whoami.exe execution for system discovery
- EID 1 captures cmd.exe with the full registry modification command
- EID 1 captures reg.exe with identical command line arguments

**PowerShell Activity:**
- Security 4703 shows token privilege adjustment for the PowerShell process
- PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass)
- Multiple Sysmon EID 7 events show .NET Framework and PowerShell module loading

**Process Access Events:**
- Sysmon EID 10 shows PowerShell accessing both child processes (whoami.exe and cmd.exe) with full access rights (0x1FFFFF)

## What This Dataset Does Not Contain

**Registry Monitoring:** The dataset lacks Sysmon EID 13 (Registry value set) or EID 12 (Registry object create/delete) events that would directly capture the registry modification. This suggests the sysmon-modular configuration does not monitor registry changes to the Policies\Explorer key, which limits visibility into the actual technique execution.

**File System Impact:** No file creation events related to the registry change itself, as Windows registry modifications don't typically generate file system events beyond the normal process operations captured.

**Network Activity:** No network connections or DNS queries, as this is purely a local system configuration change.

## Assessment

This dataset provides strong process-level visibility but lacks the most critical telemetry for detecting registry modifications—the actual registry change events. The Security and Sysmon process creation events offer excellent command line visibility, making this useful for detecting the execution method. However, without registry monitoring, you cannot confirm the technique succeeded or detect direct registry modifications bypassing command-line tools.

The process chain is clearly captured and would support detection rules focused on reg.exe usage or command lines containing registry paths related to Windows policies. The dataset would be significantly stronger with Sysmon registry monitoring configured.

## Detection Opportunities Present in This Data

1. **Command Line Analysis** - Security 4688 and Sysmon EID 1 events containing `reg add` operations targeting `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

2. **Process Chain Detection** - PowerShell spawning cmd.exe which spawns reg.exe, indicating potential script-based registry manipulation

3. **Registry Tool Usage** - Execution of reg.exe with policy-related registry paths, particularly in the Explorer policies hive

4. **Privilege Escalation Context** - Security 4703 token adjustment events preceding registry modification attempts by SYSTEM-level processes

5. **Process Access Patterns** - Sysmon EID 10 showing PowerShell accessing child processes with full rights during registry operations

6. **PowerShell Execution Context** - PowerShell process execution combined with immediate registry tool usage, indicating automated registry manipulation
