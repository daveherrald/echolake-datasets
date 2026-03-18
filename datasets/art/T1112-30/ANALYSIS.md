# T1112-30: Modify Registry — Windows HideSCAPower Group Policy Feature

## Technique Context

T1112 (Modify Registry) is a fundamental persistence and defense evasion technique where attackers modify Windows registry keys to maintain access, hide malicious activity, or alter system behavior. This specific test (T1112-30) targets the HideSCAPower registry value, which controls the visibility of the "Switch User" and "Log Off" options in Windows' security and shutdown dialog (Ctrl+Alt+Del screen). By setting `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\HideSCAPower` to 1, an attacker can hide these options from users, potentially limiting their ability to switch accounts or log off properly.

The detection community focuses heavily on registry modifications because they're both common attacker techniques and highly observable through Windows logging. Detection engineers typically monitor for modifications to policy-related registry locations, especially those that affect user interface elements or security controls.

## What This Dataset Contains

This dataset captures a successful registry modification executed via PowerShell spawning cmd.exe, which then calls reg.exe. The core activity is visible in Security event 4688 showing the command line: `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAPower /t REG_DWORD /d 1 /f`.

The process chain is clearly documented:
- PowerShell (PID 40132) → cmd.exe (PID 42172) → reg.exe (PID 29508)
- Security 4688 events capture the complete command lines for both cmd.exe and reg.exe
- Sysmon EID 1 events provide additional process creation details with hashes and parent-child relationships

Sysmon captures the reg.exe process creation with RuleName "technique_id=T1012,technique_name=Query Registry", though this is technically a registry modification, not just a query. PowerShell activity is minimal, showing only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) in the script block logging.

## What This Dataset Does Not Contain

The dataset lacks the actual registry write event itself. Neither Sysmon EID 13 (RegistryEvent - Value Set) nor Security audit events for object access are captured, likely because the audit policy shows "object_access: none". This is a significant gap since the registry modification is the core malicious activity.

Windows Defender is active but didn't block this benign registry modification, so there are no blocked execution events (STATUS_ACCESS_DENIED). The Sysmon configuration uses include-mode filtering for ProcessCreate events, but all three processes (powershell.exe, cmd.exe, reg.exe) are captured because they match the known-suspicious patterns in the sysmon-modular config.

## Assessment

This dataset provides excellent process-level telemetry for detecting this registry modification technique through command-line analysis. The Security 4688 events with command-line logging offer the strongest detection value, clearly showing the reg.exe execution with the specific HideSCAPower registry path and value.

However, the lack of registry write telemetry significantly limits the dataset's utility for comprehensive registry modification detection. Defenders would need to rely on process creation events rather than the actual registry changes, which could miss more sophisticated registry modification techniques that don't use command-line tools.

The dataset is most valuable for demonstrating process-based detection approaches and understanding how legitimate Windows tools can be chained together for registry manipulation.

## Detection Opportunities Present in This Data

1. **Registry Tool Command Line Analysis**: Monitor Security 4688 or Sysmon EID 1 for reg.exe executions with "add" operations targeting policy-related registry paths, specifically `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

2. **HideSCAPower-Specific Detection**: Create specific rules for reg.exe command lines containing "HideSCAPower" as this is a relatively uncommon registry value that primarily serves to hide security interface elements

3. **Policy Registry Path Monitoring**: Alert on any registry modification attempts (via reg.exe, PowerShell Set-ItemProperty, etc.) targeting `\Policies\Explorer` paths, which commonly contain user interface and security-related controls

4. **PowerShell-to-CMD Process Chain**: Detect PowerShell spawning cmd.exe with "/c" parameter followed by registry modification commands, indicating potential script-driven registry manipulation

5. **Suspicious Parent-Child Process Relationships**: Monitor for reg.exe spawned by cmd.exe when cmd.exe was spawned by PowerShell, especially with registry add operations targeting policy locations
