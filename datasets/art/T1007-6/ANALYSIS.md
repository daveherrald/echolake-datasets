# T1007-6: System Service Discovery — schtasks

## Technique Context

T1007 System Service Discovery involves adversaries enumerating services and scheduled tasks to understand what software is installed and what automated execution mechanisms exist on a target system. The schtasks utility is a primary method for discovering scheduled tasks on Windows systems, providing detailed information about task names, triggers, actions, and execution contexts. Attackers commonly use this reconnaissance to identify persistence opportunities, understand system behavior, and locate tasks they can hijack or abuse. Detection engineers focus on monitoring execution of discovery utilities like schtasks, especially when combined with verbose output flags or when executed in rapid succession with other reconnaissance tools.

## What This Dataset Contains

This dataset captures a complete execution of `schtasks /query /fo LIST /v` through PowerShell process spawning. The technique evidence is primarily found in Security event 4688 showing the command line `"cmd.exe" /c schtasks /query /fo LIST /v` and the subsequent schtasks execution with arguments `schtasks /query /fo LIST /v`. Sysmon provides complementary process creation events with EID 1 showing the same command execution chain: PowerShell (PID 888) → cmd.exe (PID 6804) → schtasks.exe (PID 1160). The schtasks process loads taskschd.dll, captured in Sysmon EID 7, which is the Task Scheduler COM API required for task enumeration. Security events show clean process exits (EID 4689) with exit status 0x0, indicating successful execution. A Security EID 4703 event shows token privilege adjustments for the PowerShell process, including SeBackupPrivilege and SeRestorePrivilege, which are relevant for system discovery activities.

## What This Dataset Does Not Contain

The dataset lacks the actual output/results of the schtasks query, as process output is not captured in these log sources. There are no network connections or external communications since this is purely local system enumeration. File access events for reading task files from `C:\Windows\System32\Tasks\` are not present, likely filtered by the Sysmon configuration. Registry access events that might occur during task enumeration are also absent. The PowerShell channel contains only execution policy bypass boilerplate rather than any script content that might have invoked the discovery command.

## Assessment

The dataset provides solid process execution telemetry for detecting schtasks-based discovery through both Security 4688 command-line auditing and Sysmon process creation events. The complete process chain from PowerShell through cmd.exe to schtasks is well-documented with precise command-line arguments. The taskschd.dll image load event adds another detection point specific to Task Scheduler API usage. However, the lack of task enumeration output limits understanding of what an adversary actually discovered. The relatively short 6-second execution window and clean process exits suggest this was successful reconnaissance rather than a blocked attempt.

## Detection Opportunities Present in This Data

1. Process creation of schtasks.exe with `/query` parameter in Security 4688 or Sysmon EID 1 events, especially when combined with verbose output flags like `/fo LIST /v`

2. Command shell invocation of schtasks through cmd.exe with `/c` flag, indicating potential scripted or automated discovery execution

3. PowerShell spawning discovery utilities like schtasks as child processes, detectable through parent-child process relationships

4. Loading of taskschd.dll library in unexpected processes or contexts beyond normal task execution, captured in Sysmon EID 7 events

5. Process access events (Sysmon EID 10) showing PowerShell accessing spawned discovery utilities with high-privilege access rights (0x1FFFFF)

6. Token privilege adjustments (Security EID 4703) in PowerShell processes that subsequently spawn system discovery tools

7. Rapid succession of process creation and termination events for common discovery utilities within short time windows
