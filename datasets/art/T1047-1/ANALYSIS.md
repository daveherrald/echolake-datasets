# T1047-1: Windows Management Instrumentation — WMI Reconnaissance Users

## Technique Context

Windows Management Instrumentation (WMI) is a powerful Windows administration interface that attackers commonly abuse for execution, persistence, and reconnaissance. T1047 encompasses various WMI attack patterns, with this specific test focusing on user enumeration via the `wmic useraccount` command. WMI reconnaissance is particularly valuable to attackers because it can query detailed system information without triggering many traditional detection mechanisms, operates with legitimate Windows tools, and can be executed remotely. Detection engineering teams typically focus on monitoring WMI process execution (wmic.exe, wmiprvse.exe), WMI event subscriptions for persistence, and unusual WMI queries that reveal reconnaissance intent.

## What This Dataset Contains

This dataset captures a PowerShell-initiated WMI user enumeration attack through the following process chain: `powershell.exe` → `cmd.exe` → `wmic.exe useraccount get /ALL /format:csv`. The key evidence appears in:

**Security Channel (EID 4688):** Complete process creation chain with command lines:
- `wmic  useraccount get /ALL /format:csv` (PID 27220, parent cmd.exe)
- `"cmd.exe" /c wmic useraccount get /ALL /format:csv` (PID 26824, parent powershell.exe)
- `"C:\Windows\system32\whoami.exe"` (PID 26848, also spawned by PowerShell)

**Sysmon Channel:** Process creation events for the WMI reconnaissance tools (EID 1), including a critical wmic.exe process with RuleName mapping to T1047. Process access events (EID 10) show PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF). Image load events (EID 7) capture wmic.exe loading WMI-related DLLs including `wmiutils.dll` with T1047 rule mapping.

**Privilege Escalation Evidence:** Security EID 4703 events show token right adjustments for wmic.exe, enabling powerful privileges including SeSecurityPrivilege, SeBackupPrivilege, and SeTakeOwnershipPrivilege.

**PowerShell Channel:** Contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual WMI commands.

## What This Dataset Does Not Contain

The dataset lacks several elements that would provide a more complete picture of WMI reconnaissance. There are no WMI provider logs from the Microsoft-Windows-WMI-Activity channel, which would show the actual WQL queries executed. The output of the wmic command (user account details in CSV format) is not captured in any log channel. Network-related telemetry is absent, which would be present if this were remote WMI reconnaissance. The sysmon-modular configuration's include-mode filtering means some child processes of wmic.exe may not have generated ProcessCreate events if they didn't match suspicious patterns.

## Assessment

This dataset provides excellent coverage for detecting WMI-based user reconnaissance through process monitoring. The combination of Security 4688 events with full command-line logging and Sysmon 1 events with T1047 rule mappings creates strong detection opportunities. The privilege adjustment events (4703) add valuable context about the elevated capabilities WMI tools acquire. However, the dataset would be significantly strengthened by WMI operational logs and network monitoring if targeting remote WMI abuse. The process execution telemetry alone provides sufficient evidence for detecting this reconnaissance pattern in most environments.

## Detection Opportunities Present in This Data

1. **WMI User Enumeration Command Detection** - Monitor Security 4688 for wmic.exe with command lines containing "useraccount get", particularly with output formatting options like "/format:csv"

2. **Suspicious PowerShell-to-WMI Process Chain** - Alert on powershell.exe spawning cmd.exe which then spawns wmic.exe, especially when targeting user enumeration functions

3. **WMI Reconnaissance Tool Execution** - Track Sysmon EID 1 ProcessCreate events for wmic.exe with RuleName containing "T1047" and command lines indicating reconnaissance

4. **WMI Privilege Escalation Monitoring** - Correlate Security EID 4703 token right adjustments for wmic.exe processes, particularly when high-privilege rights like SeSecurityPrivilege are enabled

5. **WMI DLL Loading Patterns** - Monitor Sysmon EID 7 for wmic.exe loading wmiutils.dll and other WMI-related libraries as indicators of WMI functionality activation

6. **Cross-Process Access from PowerShell** - Alert on Sysmon EID 10 process access events where PowerShell accesses cmd.exe or wmic.exe with full access rights (0x1FFFFF)

7. **User Discovery Tool Correlation** - Combine detections for both whoami.exe and wmic useraccount execution from the same parent PowerShell process to identify comprehensive user reconnaissance
