# T1112-19: Modify Registry — Activate Windows NoRun Group Policy Feature

## Technique Context

T1112 (Modify Registry) is a versatile technique used by attackers for both defense evasion and persistence. By modifying Windows registry keys, adversaries can disable security controls, establish persistence mechanisms, or alter system behavior to support their objectives. The specific test implemented here activates the Windows NoRun Group Policy feature by setting the `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoRun` registry value to 1. This policy prevents users from accessing the Windows Run dialog (Windows+R), potentially limiting administrative capabilities and hindering incident response efforts. While primarily a defense evasion technique, this modification persists across reboots and can serve as a persistence mechanism by maintaining reduced system functionality.

The detection community focuses on monitoring registry modifications to sensitive policy locations, process execution patterns involving registry tools, and command-line arguments that indicate policy manipulation. This particular modification is notable because it targets user experience rather than core security controls, making it potentially less obvious to defenders while still providing tactical advantage to attackers.

## What This Dataset Contains

The dataset captures a complete process execution chain implementing the registry modification technique. The attack begins with PowerShell (PID 26468) executing the command `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRun /t REG_DWORD /d 1 /f`. This spawns cmd.exe (PID 16424) which then executes reg.exe (PID 25144) with the identical command line: `reg  add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRun /t REG_DWORD /d 1 /f`.

Security events provide comprehensive process creation telemetry through EID 4688 events, capturing the full command lines and parent-child relationships. Sysmon EID 1 events complement this with process creation details for cmd.exe and reg.exe, tagged with appropriate MITRE technique identifiers (T1059.003 for Windows Command Shell and T1012 for Query Registry). Both tools are properly classified as Living Off The Land Binaries (LOLBins) in the Sysmon configuration.

The PowerShell channel contains typical test framework boilerplate with Set-ExecutionPolicy commands and Set-StrictMode scriptblocks, but no evidence of the actual registry modification command execution within PowerShell itself. A whoami.exe execution (PID 12004) appears in the timeline, likely for environmental reconnaissance.

## What This Dataset Does Not Contain

This dataset lacks the most critical telemetry for T1112 detection: actual registry modification events. Windows does not generate Security 4657 (registry value modification) events by default, and the audit policy shows "object_access: none", meaning registry auditing is disabled. Sysmon registry events (EIDs 12, 13, 14) are also absent, indicating the sysmon-modular configuration does not monitor the specific registry path targeted by this technique.

The dataset contains no evidence of the technique's success or failure - there are no registry creation, modification, or deletion events to confirm whether the NoRun policy was actually applied. Process exit codes show successful termination (0x0) but this only indicates the processes completed, not that the registry modification succeeded.

Windows Defender shows no blocking behavior, as evidenced by the clean process exits and absence of access denied errors. The technique appears to have executed without endpoint protection intervention.

## Assessment

This dataset provides excellent process execution telemetry but fundamentally incomplete coverage for T1112 detection. While you can detect the use of reg.exe with policy-related command lines, you cannot confirm the actual registry modification occurred or build detections around the registry change itself. The process-based telemetry is high quality, with comprehensive command-line logging and parent-child process relationships clearly captured across both Security and Sysmon channels.

For detection engineering focused on T1112, this dataset demonstrates the critical importance of enabling registry auditing or Sysmon registry monitoring. The process execution patterns are valuable for behavioral detection but insufficient for complete technique coverage. Organizations relying solely on process monitoring would miss successful registry modifications executed through legitimate tools.

## Detection Opportunities Present in This Data

1. **reg.exe execution with policy-related registry paths** - Monitor Sysmon EID 1 and Security EID 4688 for reg.exe processes with command lines containing "Policies\Explorer" or other sensitive policy locations

2. **cmd.exe spawning registry modification tools** - Detect cmd.exe processes that spawn reg.exe with "add" operations, particularly when targeting user or system policy hives

3. **PowerShell process spawning cmd.exe chains for registry operations** - Monitor for PowerShell processes that create cmd.exe children which subsequently execute registry tools, indicating potential script-driven registry manipulation

4. **Registry tool execution with force flags** - Look for reg.exe processes using the "/f" (force) parameter, which bypasses user confirmation and may indicate automated or malicious modification attempts

5. **NoRun-specific policy manipulation** - Create specific detection for reg.exe command lines targeting the NoRun value in Explorer policies, as this is a known technique for limiting user capabilities

6. **Process access patterns during registry operations** - The Sysmon EID 10 events show PowerShell accessing spawned processes with full access rights (0x1FFFFF), which could indicate scripted process management during registry manipulation campaigns
