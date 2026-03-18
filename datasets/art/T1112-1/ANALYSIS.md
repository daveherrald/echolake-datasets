# T1112-1: Modify Registry — Modify Registry

## Technique Context

T1112 Modify Registry is a fundamental technique attackers use to alter Windows registry keys and values for defense evasion and persistence. The registry serves as a central database for Windows configuration data, making it an attractive target for malicious modifications. Common attack patterns include disabling security features, establishing persistence mechanisms, hiding malicious artifacts, or changing system behavior to facilitate further compromise.

The detection community typically focuses on monitoring registry modifications to sensitive keys such as Run keys (persistence), security policy settings (defense evasion), logging configurations, and Windows Defender settings. This technique is frequently observed in conjunction with other defense evasion techniques and is often one of the first actions taken by attackers to establish a foothold.

## What This Dataset Contains

This dataset captures a simple registry modification operation where the HideFileExt value is set to 1 in the Windows Explorer Advanced settings. The key telemetry includes:

**Process Chain Evidence:**
- Security 4688 shows PowerShell (PID 0x4e8) spawning cmd.exe with command line `"cmd.exe" /c reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /t REG_DWORD /v HideFileExt /d 1 /f`
- Security 4688 shows cmd.exe (PID 0x45c) spawning reg.exe with command line `reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /t REG_DWORD /v HideFileExt /d 1 /f`
- Sysmon EID 1 captures both process creation events with identical command line details
- All processes execute with NT AUTHORITY\SYSTEM privileges and exit cleanly (Status 0x0)

**PowerShell Activity:**
- PowerShell script block logging (EID 4104) contains only test framework boilerplate (`Set-StrictMode -Version 1`) 
- PowerShell command invocation logging (EID 4103) shows `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`
- No evidence of the actual registry modification command in PowerShell logs

**Process Access Monitoring:**
- Sysmon EID 10 shows PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF), indicating process monitoring/interaction

## What This Dataset Does Not Contain

This dataset lacks several critical elements for comprehensive registry monitoring:

**Registry Modification Events:** No Sysmon EID 13 (Registry value set) or EID 12 (Registry object added/deleted) events are present, despite the sysmon-modular configuration typically capturing registry changes. This suggests either the registry modification didn't trigger Sysmon's filters or the specific registry key wasn't monitored.

**Object Access Auditing:** No Security EID 4656/4663 events for registry object access, as the audit policy shows "object_access: none" - this is the primary Windows-native method for tracking registry modifications.

**Success Confirmation:** No telemetry confirms whether the registry modification actually succeeded, only that the reg.exe process was launched and exited with status 0x0.

## Assessment

This dataset provides limited utility for T1112 detection engineering. While it captures the process execution chain leading to a registry modification attempt, it lacks the actual registry change telemetry that would be most valuable for detection. The command-line evidence in Security 4688 events is the strongest detection signal present.

For building robust T1112 detections, this data would need to be supplemented with proper Sysmon registry monitoring (EIDs 12/13) or Windows object access auditing. The dataset does demonstrate how attackers might use native tools like reg.exe through command shell proxies to perform registry modifications.

## Detection Opportunities Present in This Data

1. **Process creation monitoring for reg.exe** - Security EID 4688 and Sysmon EID 1 showing reg.exe launched with "add" operations targeting sensitive registry paths like HKEY_CURRENT_USER\Software\Microsoft\Windows

2. **Command-line analysis for registry modification patterns** - Detection of cmd.exe spawning reg.exe with specific flags (/t REG_DWORD, /f for force) and registry paths associated with security or visibility settings

3. **Process chain analysis** - PowerShell → cmd.exe → reg.exe execution chain, particularly when PowerShell is running with SYSTEM privileges but modifying HKEY_CURRENT_USER

4. **Suspicious registry target detection** - Commands targeting Explorer\Advanced settings, particularly HideFileExt which is commonly modified to hide malicious file extensions

5. **Process access monitoring** - Sysmon EID 10 showing PowerShell accessing child processes with full privileges (0x1FFFFF), indicating potential process injection or monitoring capabilities

6. **PowerShell execution policy bypass detection** - PowerShell EID 4103 showing Set-ExecutionPolicy with Bypass, often indicating preparation for malicious script execution
