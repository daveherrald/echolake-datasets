# T1112-27: Modify Registry — Hide Windows Clock Group Policy Feature

## Technique Context

T1112 (Modify Registry) is a foundational technique used by attackers to establish persistence, evade defenses, and modify system behavior. This specific test demonstrates hiding the Windows clock through registry modification, which falls under defense evasion tactics. Attackers commonly modify registry keys in `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` to alter user interface elements, disable security features, or hide system components. The detection community focuses on monitoring registry modifications to policy-related keys, particularly those that affect system visibility and security controls.

## What This Dataset Contains

This dataset captures the execution of a registry modification that hides the Windows clock by setting the `HideClock` registry value. The core activity is visible in Security event 4688 showing the command execution:

```
"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideClock /t REG_DWORD /d 1 /f
```

The process chain shows PowerShell spawning cmd.exe (PID 36512), which then spawns reg.exe (PID 27068) to perform the actual registry modification. Sysmon captures this chain with ProcessCreate events (EIDs 1) for cmd.exe and reg.exe, both tagged with relevant MITRE technique classifications (`technique_id=T1059.003` for Command Shell and `technique_id=T1012` for Query Registry).

Process access events (Sysmon EID 10) show PowerShell accessing both the cmd.exe and whoami.exe processes with full access rights (`GrantedAccess: 0x1FFFFF`). The PowerShell events contain only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) with no technique-specific script content.

## What This Dataset Does Not Contain

Critically, this dataset lacks the actual registry modification telemetry. There are no Sysmon EID 13 (Registry Value Set) events that would capture the creation of the `HideClock` value. This indicates that either the sysmon-modular configuration doesn't monitor this specific registry path, or the registry modification occurs in a context that Sysmon doesn't capture for HKCU modifications when running as SYSTEM.

The dataset also doesn't contain any Windows Defender blocking events or error conditions—the reg.exe process exits cleanly with status 0x0, suggesting the registry modification succeeded despite the lack of direct registry telemetry.

## Assessment

This dataset provides moderate detection value focused on process execution patterns rather than registry monitoring. The primary detection opportunities lie in the command-line arguments and process relationships captured in Security 4688 and Sysmon EID 1 events. However, the absence of actual registry modification telemetry significantly limits the dataset's utility for comprehensive T1112 detection engineering.

The process execution telemetry is high quality, showing clear parent-child relationships and complete command lines. This makes it valuable for detecting the specific technique execution method, but less useful for understanding the registry impact or building detections around registry changes themselves.

## Detection Opportunities Present in This Data

1. **Registry Policy Modification via Command Line** - Security 4688 and Sysmon EID 1 events capture `reg.exe` with command line containing `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` and policy-related values like `HideClock`

2. **PowerShell Process Spawning Registry Tools** - Process chain analysis showing powershell.exe spawning cmd.exe spawning reg.exe with policy modification arguments

3. **Process Access to Registry Utilities** - Sysmon EID 10 events showing PowerShell accessing cmd.exe and reg.exe processes with full access rights during registry operations

4. **Registry Command Pattern Analysis** - Command line patterns matching `reg add` operations targeting user policy registry paths with specific flags (`/v`, `/t REG_DWORD`, `/d`, `/f`)

5. **System Context Policy Modifications** - Process execution under SYSTEM context modifying HKCU policy keys, which may indicate privilege escalation or system-level persistence attempts
