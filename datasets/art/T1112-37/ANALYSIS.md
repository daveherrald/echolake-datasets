# T1112-37: Modify Registry — Disable Windows Security Center Notifications

## Technique Context

T1112 Modify Registry is a defense evasion and persistence technique where adversaries alter Windows registry entries to change system behavior, disable security features, or maintain persistence. This specific test targets the Windows Security Center notification system by modifying the `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\ImmersiveShell` registry key to disable Action Center experience notifications.

Security Center notifications alert users to security issues like disabled antivirus, missing updates, or firewall problems. Disabling these notifications is a common adversary tactic to reduce user awareness of security posture changes they've made. The detection community focuses on monitoring registry modifications to security-related keys, especially those affecting Windows Defender, Security Center, and notification systems. This technique is often paired with other defense evasion methods like disabling security services or modifying security policies.

## What This Dataset Contains

This dataset captures a successful registry modification attack executed through PowerShell and the Windows reg.exe utility. The attack chain shows:

**Process execution chain captured in Security 4688 events:**
- PowerShell spawns cmd.exe: `"cmd.exe" /c reg add HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\ImmersiveShell /v UseActionCenterExperience /t REG_DWORD /d 0 /f`
- cmd.exe spawns reg.exe: `reg add HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\ImmersiveShell /v UseActionCenterExperience /t REG_DWORD /d 0 /f`

**Sysmon telemetry includes:**
- Multiple PowerShell process creations and .NET assembly loads (EID 1, 7)
- Process access events showing PowerShell accessing child processes (EID 10)
- cmd.exe process creation (ProcessId 11248) spawning reg.exe (ProcessId 13860)
- Successful exit codes (0x0) for all processes indicating successful execution

**Additional context:**
- whoami.exe execution for user discovery before the registry modification
- All processes executed under NT AUTHORITY\SYSTEM context
- PowerShell script block logging shows only test framework boilerplate (`Set-ExecutionPolicy Bypass`)

## What This Dataset Does Not Contain

This dataset lacks the most critical telemetry for this technique - the actual registry modification events. The dataset contains no Sysmon Event ID 13 (Registry value set) or Event ID 12 (Registry key/value create/delete) events that would show the specific registry change being made to the `UseActionCenterExperience` value.

The absence of registry modification events suggests the sysmon-modular configuration used in this environment doesn't monitor the `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\ImmersiveShell` registry path. Windows Security event logs also don't contain object access auditing for registry changes, as the audit policy shows object access auditing is disabled.

PowerShell script block logging captured only execution policy changes rather than the actual registry modification commands, indicating the technique was executed through cmd.exe/reg.exe rather than PowerShell cmdlets like Set-ItemProperty.

## Assessment

This dataset provides limited utility for building detections specific to Windows Security Center notification disabling. While it captures the process execution chain showing reg.exe being used to modify registry values, it lacks the registry change telemetry that would definitively identify this technique. 

The Security 4688 command-line logging is the primary detection signal here, showing the specific registry path and value being modified. However, this relies on attackers using reg.exe rather than direct API calls or PowerShell registry cmdlets, which may not always be the case.

For stronger detection coverage of T1112, organizations would need Sysmon registry monitoring enabled for security-relevant paths or Windows object access auditing configured for registry operations. The current telemetry is better suited for detecting suspicious process execution patterns than the specific registry modifications that define this technique.

## Detection Opportunities Present in This Data

1. **Command-line detection of reg.exe modifying Security Center paths** - Security 4688 events show reg.exe with command line containing "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\ImmersiveShell" and "UseActionCenterExperience"

2. **Suspicious PowerShell spawning reg.exe** - Process creation chain showing PowerShell → cmd.exe → reg.exe for registry modifications, captured in both Security 4688 and Sysmon 1 events

3. **System-level registry modification activity** - Processes running under NT AUTHORITY\SYSTEM context performing registry changes, which may be unusual outside of system maintenance windows

4. **reg.exe execution with administrative registry paths** - Sysmon 1 events showing reg.exe accessing HKLM paths, particularly targeting Windows security-related registry locations

5. **Multiple PowerShell process launches in sequence** - Pattern of sequential PowerShell instances (ProcessIds 13044, 29328, 14384) potentially indicating scripted attack execution
