# T1082-35: System Information Discovery — Check OS version via "ver" command

## Technique Context

T1082 System Information Discovery is a fundamental reconnaissance technique where adversaries gather information about the operating system and computer system. The "ver" command is one of the most basic and widely used methods for OS version discovery on Windows systems. This technique is critical in the early stages of attack chains as it helps adversaries understand the target environment, select appropriate exploits, and determine privilege escalation paths. The detection community focuses on monitoring execution of system information gathering commands, particularly when executed in unusual contexts or as part of broader reconnaissance patterns.

## What This Dataset Contains

This dataset captures the execution of `cmd.exe /c ver` launched from PowerShell, providing clean telemetry for this basic system discovery technique. The Security channel shows the full process execution chain with Security 4688 events capturing the PowerShell parent (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`) spawning `"cmd.exe" /c ver` (Process ID 0x11d4). Sysmon provides complementary coverage with EID 1 ProcessCreate events showing the same command line `"cmd.exe" /c ver` with full process ancestry back to the PowerShell parent.

The dataset also captures a secondary discovery command execution - `whoami.exe` (Process ID 0x1af4) - providing additional context for typical reconnaissance patterns. Both commands execute with SYSTEM privileges under the NT AUTHORITY\SYSTEM security context.

Sysmon EID 10 ProcessAccess events show PowerShell accessing both spawned processes with full access rights (0x1FFFFF), indicating normal parent-child process relationships. The PowerShell channel contains only execution policy setup boilerplate (`Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`) without capturing the actual command invocations.

## What This Dataset Does Not Contain

The dataset lacks the actual output or results of the "ver" command - we see process creation and termination but not the OS version information that would be displayed to the user. There are no Sysmon ProcessCreate events for the PowerShell processes themselves, as the sysmon-modular configuration's include-mode filtering doesn't trigger on PowerShell.exe. The dataset contains no network activity, file system modifications, or registry operations beyond basic PowerShell startup artifacts. The PowerShell script block logging doesn't capture the actual "ver" command execution, only the initial execution policy configuration.

## Assessment

This dataset provides excellent coverage for detecting basic system information discovery via the "ver" command. The combination of Security 4688 and Sysmon EID 1 events gives defenders multiple detection vectors with full command-line visibility and process ancestry. The clean execution (no blocking by Defender) ensures complete technique telemetry from start to finish. While the technique itself is simple, the quality of process monitoring data makes this dataset valuable for building detections around reconnaissance patterns, particularly when combined with other discovery commands like "whoami".

## Detection Opportunities Present in This Data

1. **Command-line pattern matching** - Security 4688 and Sysmon EID 1 events containing `cmd.exe` with `/c ver` parameter combination
2. **Process ancestry analysis** - PowerShell spawning cmd.exe for system information gathering, indicating potential reconnaissance activity
3. **Multiple discovery command correlation** - Sequential execution of "whoami" followed by "ver" commands suggests systematic reconnaissance
4. **Privilege context monitoring** - System information discovery commands running under SYSTEM privileges may indicate post-exploitation activity
5. **Process access patterns** - Sysmon EID 10 events showing PowerShell accessing spawned discovery processes with full permissions
6. **Discovery command clustering** - Multiple system information gathering utilities executed within short time windows from the same parent process
