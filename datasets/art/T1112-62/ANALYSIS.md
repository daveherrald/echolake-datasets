# T1112-62: Modify Registry — Activities To Disable Microsoft FIDO Authentication

## Technique Context

T1112 (Modify Registry) is a fundamental technique used by adversaries to alter system configurations, disable security features, establish persistence, and evade defensive measures. FIDO (Fast IDentity Online) authentication represents a modern approach to multi-factor authentication using hardware security keys or biometric devices. Disabling FIDO authentication through registry modification removes an important security control that organizations deploy to strengthen authentication beyond traditional passwords.

Attackers commonly target authentication-related registry settings to weaken security posture during initial access or privilege escalation phases. The specific registry modification in this test (`HKLM\SOFTWARE\Policies\Microsoft\FIDO\AllowExternalDeviceSignon`) controls whether external FIDO devices can be used for authentication. Setting this to 0 effectively disables FIDO authentication, forcing users back to potentially weaker authentication methods. Detection engineers focus on monitoring registry modifications to security-related keys, particularly those affecting authentication mechanisms, antivirus settings, and logging configurations.

## What This Dataset Contains

This dataset captures a straightforward registry modification executed through PowerShell invoking cmd.exe and reg.exe. The process chain shows `powershell.exe` → `cmd.exe` → `reg.exe` with the command line `reg add "HKLM\SOFTWARE\Policies\Microsoft\FIDO" /v "AllowExternalDeviceSignon" /t REG_DWORD /d 0 /f`.

Key telemetry includes:
- **Sysmon EID 1**: Process creation for cmd.exe with full command line: `"cmd.exe" /c reg add "HKLM\SOFTWARE\Policies\Microsoft\FIDO" /v "AllowExternalDeviceSignon" /t REG_DWORD /d 0 /f`
- **Sysmon EID 1**: Process creation for reg.exe with command line: `reg add "HKLM\SOFTWARE\Policies\Microsoft\FIDO" /v "AllowExternalDeviceSignon" /t REG_DWORD /d 0 /f`
- **Security EID 4688**: Corresponding process creation events with command line logging for both cmd.exe and reg.exe
- **Sysmon EID 10**: Process access events showing PowerShell accessing both child processes with full access rights (0x1FFFFF)
- **Multiple Sysmon EID 7**: Image load events showing .NET framework loading for PowerShell execution

All processes execute under `NT AUTHORITY\SYSTEM` context with high integrity, indicating administrative privilege level required for this registry modification.

## What This Dataset Does Not Contain

The dataset lacks the most critical telemetry for T1112 detection: actual registry modification events. There are no Sysmon EID 13 (Registry value set) events capturing the registry write operation itself. This absence likely results from the default sysmon-modular configuration not monitoring the `HKLM\SOFTWARE\Policies\Microsoft\FIDO` registry path.

Additionally missing:
- Registry object access events (Security EID 4657) that would show the specific registry value being modified
- Any registry creation events (Sysmon EID 12) if the FIDO key didn't previously exist
- PowerShell script block content beyond test framework boilerplate (the actual Atomic Red Team script content is not captured)

The PowerShell channel contains only execution policy changes and error handling scriptblocks, not the substantive commands that initiated the registry modification.

## Assessment

This dataset provides moderate utility for detection engineering focused on process-based indicators of registry modification attempts. While it successfully captures the process execution chain and command lines that clearly indicate malicious intent to disable FIDO authentication, the absence of actual registry modification telemetry significantly limits its value for comprehensive T1112 detection.

The process telemetry is excellent quality, with complete command lines, parent-child relationships, and process access events that would support behavioral detection. However, for a registry modification technique, the lack of registry monitoring makes this dataset incomplete for demonstrating the full attack lifecycle. Detection engineers could use this data to build process-based detections but would need to supplement with registry monitoring for complete coverage.

## Detection Opportunities Present in This Data

1. **Suspicious reg.exe Command Line**: Monitor for reg.exe execution with "add" operations targeting security-related registry paths, specifically `HKLM\SOFTWARE\Policies\Microsoft\FIDO` with value "AllowExternalDeviceSignon"

2. **FIDO Authentication Disabling**: Alert on registry modifications that set `AllowExternalDeviceSignon` to 0, indicating potential attempt to weaken authentication controls

3. **PowerShell Child Process Chain**: Detect PowerShell spawning cmd.exe which then spawns reg.exe, particularly when targeting authentication-related registry keys

4. **Administrative Registry Modification**: Monitor for SYSTEM-level processes modifying security policy registry locations under `HKLM\SOFTWARE\Policies\Microsoft\`

5. **Process Access to Registry Tools**: Track when PowerShell or other scripting engines access reg.exe processes with full privileges, potentially indicating automated registry manipulation

6. **Authentication Policy Tampering**: Correlate registry tool execution with modifications to authentication-related policy keys to detect security control bypasses
