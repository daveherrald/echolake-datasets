# T1112-53: Modify Registry — Disable Windows Auto Reboot for current logon user

## Technique Context

T1112 (Modify Registry) is a fundamental Windows defense evasion and persistence technique where adversaries alter registry keys to change system behavior, disable security features, or maintain persistence. This specific test targets the Windows Update auto-reboot functionality by setting the `NoAutoRebootWithLoggedOnUsers` policy value, which prevents automatic reboots when users are logged in - a common technique to maintain persistence and avoid disruption of ongoing operations. Detection engineers focus on monitoring registry modifications to sensitive policy areas, especially those affecting security controls, system behavior, or Windows Update mechanisms. The registry modification patterns, command-line evidence, and process chains are key detection points for this technique.

## What This Dataset Contains

This dataset captures a successful registry modification executed through PowerShell spawning cmd.exe and reg.exe. The process chain shows PowerShell (PID 21956) → cmd.exe (PID 37276) → reg.exe (PID 33888) executing `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d 1 /f`. Security event 4688 captures the full command line for both cmd.exe and reg.exe processes, while Sysmon EID 1 events provide additional process creation details including hashes and parent process relationships. The Sysmon events include process access events (EID 10) showing PowerShell accessing both child processes with full access rights (0x1FFFFF). Multiple PowerShell-related DLL loads are captured (mscoree.dll, mscoreei.dll, clr.dll, System.Management.Automation.ni.dll) indicating .NET framework initialization for PowerShell execution.

## What This Dataset Does Not Contain

The dataset lacks registry modification events (Sysmon EID 12/13) that would directly show the registry key creation or value modification, likely due to the sysmon-modular configuration not including registry monitoring rules for this specific key path. There are no Object Access audit events (4656/4658/4663) showing the actual registry access, as object access auditing is disabled according to the metadata. Windows Defender real-time protection events are absent, suggesting the technique was not flagged as malicious. The PowerShell channel contains only standard boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without capturing the actual PowerShell commands that initiated the registry modification sequence.

## Assessment

The dataset provides good process-level telemetry for detecting this registry modification technique through command-line analysis and process chain monitoring. Security 4688 events with full command-line logging effectively capture the reg.exe execution with the specific registry path and value being modified. Sysmon process creation events add valuable context with file hashes and parent-child relationships. However, the absence of direct registry modification events significantly limits the dataset's utility for registry-focused detections. The combination of process telemetry sources provides sufficient evidence for detection, but defenders would benefit from enabling Sysmon registry monitoring or Windows Object Access auditing for more comprehensive coverage.

## Detection Opportunities Present in This Data

1. **Registry Tool Command Line Detection** - Monitor Security 4688 or Sysmon EID 1 for reg.exe processes with command lines containing "NoAutoRebootWithLoggedOnUsers" or modifications to "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

2. **Windows Update Policy Modification** - Detect processes modifying Windows Update policy registry keys, particularly those affecting auto-reboot behavior

3. **PowerShell Child Process Chain** - Monitor for PowerShell spawning cmd.exe which then spawns reg.exe, indicating potential scripted registry modifications

4. **Registry Tool Parent Process Analysis** - Flag reg.exe processes with unexpected parent processes like cmd.exe spawned from PowerShell or other scripting engines

5. **Windows Update Registry Path Monitoring** - Create alerts for any process accessing or modifying the "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" registry path

6. **Token Privilege Escalation** - Monitor Security 4703 events showing processes enabling multiple system privileges (SeBackupPrivilege, SeRestorePrivilege, etc.) before registry modifications
