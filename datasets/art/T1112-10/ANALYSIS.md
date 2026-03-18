# T1112-10: Modify Registry — Disable Windows Registry Tool

## Technique Context

T1112 (Modify Registry) represents a fundamental technique used by attackers to alter Windows registry settings for defense evasion and persistence. This specific test (T1112-10) focuses on disabling the Windows Registry Editor (regedit.exe) by setting the `DisableRegistryTools` registry value, preventing users from accessing registry editing tools through the GUI. This is a common administrative restriction that attackers might implement to hinder incident response efforts and prevent registry-based remediation. The detection community typically focuses on monitoring registry modifications to policy-related keys, especially those that disable security tools or administrative utilities.

## What This Dataset Contains

The dataset captures a complete execution chain showing the registry modification technique. Security Event ID 4688 shows PowerShell spawning cmd.exe with the command line `"cmd.exe" /c reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\policies\system /v DisableRegistryTools /t REG_DWORD /d 1 /f`, followed by cmd.exe creating reg.exe with the command `reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\policies\system /v DisableRegistryTools /t REG_DWORD /d 1 /f`.

Sysmon provides excellent telemetry with Event ID 1 (ProcessCreate) capturing both cmd.exe (PID 12156) and reg.exe (PID 14876) creation with full command lines. Most critically, Sysmon Event ID 13 (RegistryEvent) captures the actual registry modification: `HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\policies\system\DisableRegistryTools` set to `DWORD (0x00000001)`. The dataset also includes Sysmon Event ID 10 showing PowerShell accessing both child processes with PROCESS_ALL_ACCESS (0x1FFFFF), and Event ID 11 showing PowerShell profile file creation.

## What This Dataset Does Not Contain

The dataset shows the registry key being set under `HKU\.DEFAULT` (the default user hive) rather than `HKEY_CURRENT_USER` as specified in the command line, which indicates the technique executed under the SYSTEM context rather than a user context. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no evidence of the actual technique execution. There are no registry query operations or attempts to verify the setting took effect, and no evidence of the technique being tested (such as attempting to launch regedit.exe).

## Assessment

This dataset provides excellent telemetry for detecting registry-based tool disabling techniques. The combination of Security Event 4688 command-line logging, Sysmon ProcessCreate events, and Sysmon RegistryEvent monitoring creates multiple detection points across the execution chain. The registry modification is clearly visible in Sysmon Event ID 13, which is the gold standard for registry-based detections. The process tree (PowerShell → cmd.exe → reg.exe) is fully captured, and the specific policy key modification is logged with complete details including the target registry path and DWORD value.

## Detection Opportunities Present in This Data

1. **Registry Policy Modification Detection** - Monitor Sysmon Event ID 13 for modifications to `*\policies\system\DisableRegistryTools` with value 1, indicating administrative tool disabling

2. **Command Line Analysis** - Detect Security Event ID 4688 or Sysmon Event ID 1 with command lines containing `reg add` operations targeting policy keys, specifically `DisableRegistryTools`

3. **Process Chain Analysis** - Monitor for PowerShell spawning cmd.exe which subsequently spawns reg.exe, particularly when targeting administrative policy modifications

4. **Administrative Tool Disabling Pattern** - Create alerts for registry modifications that disable built-in Windows administrative tools under `*\policies\system\` keys

5. **Cross-Process Access Monitoring** - Use Sysmon Event ID 10 to detect PowerShell accessing newly created registry tool processes with high privileges (PROCESS_ALL_ACCESS)

6. **Policy Hive Modifications** - Monitor for any registry changes under `.DEFAULT` or current user policy paths that modify system administration capabilities
