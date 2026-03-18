# T1112-38: Modify Registry — Suppress Win Defender Notifications

## Technique Context

T1112 (Modify Registry) is a fundamental technique used by attackers to alter Windows registry keys and values for defense evasion and persistence. The specific test case focuses on suppressing Windows Defender notifications by creating the `Notification_Suppress` DWORD value under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration`. This technique is commonly employed by malware to reduce user awareness of security alerts and maintain stealth during operations. Detection engineers typically focus on monitoring registry modifications to security-related keys, particularly those affecting endpoint protection software configuration.

## What This Dataset Contains

The dataset captures a complete execution chain showing registry modification to suppress Windows Defender notifications. The attack begins with PowerShell (PID 13916) executing `powershell.exe`, which then spawns a command shell via Security 4688: `"cmd.exe" /c reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" /v Notification_Suppress /t REG_DWORD /d 1 /f`. The cmd.exe process (PID 30044) subsequently executes reg.exe (PID 13164) with the command line `reg  add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" /v Notification_Suppress /t REG_DWORD /d 1 /f`.

The critical registry modification is captured in Sysmon 13: `Registry value set: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration\Notification_Suppress` with `Details: DWORD (0x00000001)`. Sysmon 1 events show process creation for both cmd.exe and reg.exe with their complete command lines. Additional telemetry includes Sysmon 10 process access events showing PowerShell accessing both whoami.exe and cmd.exe processes, and various DLL loading events (Sysmon 7) including Windows Defender components like MpOAV.dll and MpClient.dll.

## What This Dataset Does Not Contain

The dataset lacks certain registry-related events that could provide additional context. There are no Sysmon 12 (Registry object added or deleted) events showing the creation of the registry key structure, likely because the parent keys already existed. The dataset also doesn't contain any Windows Defender operational logs that would show the actual impact of the registry change on notification behavior. Additionally, there are no object access audit events (Security 4663) for registry operations, as the audit policy shows object access auditing is disabled.

## Assessment

This dataset provides excellent telemetry for detecting registry-based defense evasion against Windows Defender. The combination of Security 4688 command-line logging and Sysmon 13 registry monitoring creates multiple detection opportunities. The process chain is clearly visible through Security events, while Sysmon 13 provides the specific registry modification details needed for high-fidelity detection. The presence of both process creation and registry modification events allows for correlation-based detections that can reduce false positives compared to monitoring either data source alone.

## Detection Opportunities Present in This Data

1. **Registry Modification to Defender Configuration** - Sysmon 13 events targeting `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\*` keys, particularly the UX Configuration subkey used for notification suppression

2. **Reg.exe Command Line for Defender Suppression** - Security 4688 or Sysmon 1 events with command lines containing `reg add` operations targeting Windows Defender policy keys with notification-related values

3. **Process Chain Analysis** - PowerShell spawning cmd.exe which spawns reg.exe for registry modification, indicating potential scripted defense evasion activity

4. **Suspicious Registry Values** - Sysmon 13 events creating or modifying `Notification_Suppress` values under Windows Defender configuration paths

5. **Defender Component DLL Loading Correlation** - Sysmon 7 events showing Windows Defender DLL loads (MpOAV.dll, MpClient.dll) in proximity to registry modifications affecting Defender configuration
