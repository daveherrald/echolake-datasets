# T1112-36: Modify Registry — Disable Windows Toast Notifications

## Technique Context

T1112 (Modify Registry) is a fundamental technique used by attackers to alter system configuration, establish persistence, disable security features, or evade detection. Registry modifications are particularly valuable for defense evasion because they can disable Windows notification systems, logging capabilities, or security controls without requiring file drops or process injection. The detection community focuses on monitoring specific registry keys related to security controls, autostart locations, and system configuration changes. This particular test targets the Windows notification system by disabling toast notifications through the `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications` registry key, which attackers might use to reduce user awareness of system activity or security alerts.

## What This Dataset Contains

The technique execution is clearly captured through a straightforward process chain: PowerShell spawns cmd.exe, which then launches reg.exe to perform the registry modification. Security 4688 events show the complete command line progression: `"cmd.exe" /c reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications /v ToastEnabled /t REG_DWORD /d 0 /f` followed by the reg.exe process with command line `reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications /v ToastEnabled /t REG_DWORD /d 0 /f`. Sysmon ProcessCreate events (EID 1) capture both the cmd.exe and reg.exe processes with their parent-child relationships clearly established. All processes execute under NT AUTHORITY\SYSTEM context with exit status 0x0, indicating successful completion. The PowerShell events contain only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`), with no technique-specific script content captured.

## What This Dataset Does Not Contain

Critically, this dataset lacks the actual registry modification events. Neither Sysmon registry events (which would be EID 12, 13, or 14) nor Windows Security registry audit events are present, despite the successful execution of reg.exe. This absence is likely due to the Sysmon configuration focusing on process and image load monitoring rather than registry operations, and the Windows audit policy not including object access auditing for registry keys. The technique appears to execute successfully based on process exit codes, but the core evidence of the registry value creation/modification is not captured in the telemetry.

## Assessment

This dataset provides excellent process execution telemetry for registry modification techniques but critically lacks the registry operation evidence itself. The Security 4688 events with command-line logging are the strongest data source here, clearly showing the attacker's intent and the specific registry path being modified. Sysmon ProcessCreate events provide valuable parent-child process relationships and integrity level information. However, without registry monitoring enabled, defenders would need to rely on command-line analysis to detect this technique rather than monitoring the actual registry changes. This represents a common gap in many Windows environments where process monitoring is enabled but registry auditing is not configured.

## Detection Opportunities Present in This Data

1. **Command-line detection for reg.exe registry modifications** - Security 4688 events show `reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications /v ToastEnabled /t REG_DWORD /d 0` targeting notification settings
2. **Process chain analysis for indirect registry access** - PowerShell spawning cmd.exe which spawns reg.exe indicates potential scripted registry manipulation
3. **Registry tool execution monitoring** - Sysmon EID 1 events for reg.exe processes with specific command-line patterns targeting security-related registry keys
4. **Notification system tampering detection** - Command-line patterns specifically targeting the PushNotifications registry path which could indicate attempts to disable user security awareness features
5. **Privilege escalation context analysis** - All processes running under SYSTEM context while modifying user registry hives may indicate privilege misuse or token manipulation
