# T1112-29: Modify Registry — Windows HideSCANetwork Group Policy Feature

## Technique Context

T1112 (Modify Registry) is a versatile technique used by adversaries to manipulate Windows registry settings for defense evasion and persistence. The HideSCANetwork group policy feature specifically controls the visibility of network adapters in Windows network interfaces, effectively hiding network connectivity from users while maintaining functionality. This technique is particularly useful for adversaries who want to maintain covert network access while preventing users from detecting or disabling network connections. The detection community focuses on monitoring registry modifications to sensitive policy locations, especially those that affect system visibility and security settings.

## What This Dataset Contains

This dataset captures the execution of a registry modification that sets the HideSCANetwork policy. The core technique execution is visible in Security Event 4688, which shows the command line: `reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCANetwork /t REG_DWORD /d 1 /f`. The process chain shows PowerShell (PID 20596) spawning cmd.exe (PID 41220), which then executes reg.exe (PID 38992) to perform the actual registry modification.

Sysmon captures three process creation events (EID 1): whoami.exe for system discovery, cmd.exe for command shell execution, and reg.exe for registry manipulation. The Sysmon events include full command lines and process relationships, with reg.exe specifically tagged with the "Query Registry" rule (technique_id=T1012). Process access events (EID 10) show PowerShell accessing both child processes with full access rights (0x1FFFFF).

The PowerShell operational log contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without the actual technique implementation, indicating the registry modification was performed via external process execution rather than PowerShell registry cmdlets.

## What This Dataset Does Not Contain

The dataset lacks the actual registry modification telemetry. While we see the reg.exe process execution with the correct command line, there are no Sysmon Registry events (EID 12, 13, 14) showing the actual creation of the HideSCANetwork value. This is likely due to the sysmon-modular configuration not monitoring registry modifications to user policy locations, or the specific registry path not being included in the monitoring scope.

The dataset also doesn't show any Windows System events or Group Policy operational logs that might capture policy changes. There are no file creation events related to registry hive modifications, and no evidence of the policy taking effect in network adapter visibility.

## Assessment

This dataset provides excellent process execution telemetry for the registry modification technique but lacks the actual registry change evidence. The Security 4688 events with command-line logging provide the most reliable detection data, clearly showing the reg.exe execution with the specific HideSCANetwork policy modification. The Sysmon process creation and access events add valuable context about the execution chain and process relationships.

However, the absence of registry modification telemetry significantly limits the dataset's utility for comprehensive detection engineering. Defenders typically want to monitor both the process execution attempting the change and the successful registry modification itself. This dataset only provides half of that picture.

## Detection Opportunities Present in This Data

1. **Registry Tool Execution with Policy Paths** - Security 4688 showing reg.exe with command lines containing "Policies\Explorer" and "HideSCANetwork" values

2. **PowerShell Command Shell Spawning** - Sysmon EID 1 showing PowerShell spawning cmd.exe with registry modification command lines

3. **Registry Tool Process Chain** - Process creation sequence of powershell.exe → cmd.exe → reg.exe for registry manipulation

4. **High-Privilege Registry Modifications** - Security events showing SYSTEM account executing registry tools against user policy locations

5. **Process Access Patterns** - Sysmon EID 10 showing PowerShell accessing spawned processes with full access rights during registry operations

6. **Network Policy Manipulation** - Command line arguments specifically targeting HideSCANetwork with DWORD value 1 to enable hiding

7. **LOLBin Registry Usage** - Sysmon process creation events for reg.exe with administrative policy modification parameters
