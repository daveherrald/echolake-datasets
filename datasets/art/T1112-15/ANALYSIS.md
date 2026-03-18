# T1112-15: Modify Registry — Disable Windows LogOff Button

## Technique Context

T1112 (Modify Registry) represents a fundamental technique used by attackers to alter Windows system configuration through registry modifications. This specific test focuses on disabling the Windows logoff functionality by modifying Group Policy-related registry keys. The technique serves both defense evasion and persistence purposes — by preventing users from logging off normally, attackers can maintain session persistence while making it harder for users to cleanly terminate potentially compromised sessions.

The detection community focuses heavily on monitoring registry modifications to policy-related keys, particularly those under `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` and similar Group Policy enforcement locations. This technique is commonly seen in malware that aims to prevent users from easily escaping compromised sessions or in attacks where maintaining user session state is critical.

## What This Dataset Contains

The dataset captures a complete execution chain showing PowerShell launching CMD.exe to execute two registry modification commands. The primary evidence appears in Security event logs with detailed command-line auditing:

Security 4688 events show the process creation chain: `powershell.exe` → `cmd.exe` → `reg.exe` (twice). The cmd.exe process has the full command line: `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoLogOff /t REG_DWORD /d 1 /f & reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v StartMenuLogOff /t REG_DWORD /d 1 /f`

Two separate reg.exe executions are captured with their specific registry modification commands:
1. `reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoLogOff /t REG_DWORD /d 1 /f`
2. `reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v StartMenuLogOff /t REG_DWORD /d 1 /f`

Sysmon provides complementary process creation events (EID 1) for all three processes with full command lines, process access events (EID 10) showing PowerShell accessing the spawned processes, and .NET assembly loading events (EID 7) as PowerShell initializes.

## What This Dataset Does Not Contain

The dataset lacks Sysmon registry modification events (EID 13) that would directly capture the actual registry value changes. This is likely due to the sysmon-modular configuration not including registry monitoring for this specific key path. Additionally, there are no Windows System events that would show the Group Policy changes taking effect, and no user logon/logoff events that would demonstrate the technique's impact on user sessions.

The PowerShell script block logging only captures the test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) rather than the actual malicious PowerShell code that would have spawned the cmd.exe process.

## Assessment

This dataset provides excellent coverage for process-based detection of registry modification attacks. The Security event logs with command-line auditing capture the complete attack chain with sufficient detail to build robust detections. While missing direct registry modification telemetry, the process execution evidence is comprehensive and would be the primary detection method for most SOCs. The combination of parent-child process relationships, specific command-line arguments, and registry key targets provides multiple high-fidelity detection opportunities.

## Detection Opportunities Present in This Data

1. **Registry Policy Modification via REG.exe** - Security 4688 events showing reg.exe processes with command lines containing "Policies\Explorer" and specific policy values like "NoLogOff" or "StartMenuLogOff"

2. **CMD.exe with Registry Modification Commands** - Security 4688 events showing cmd.exe processes with command lines containing both "reg add" and "Policies\Explorer" indicating batch registry policy changes

3. **PowerShell Spawning Registry Utilities** - Process creation chains where powershell.exe creates cmd.exe which then creates reg.exe, particularly when targeting policy registry locations

4. **Group Policy Bypass Attempt** - Combined detection of both NoLogOff and StartMenuLogOff registry modifications occurring within a short time window, indicating deliberate logoff prevention

5. **Suspicious Process Access Patterns** - Sysmon EID 10 events showing PowerShell accessing registry utility processes with full access rights (0x1FFFFF), potentially indicating process injection or monitoring
