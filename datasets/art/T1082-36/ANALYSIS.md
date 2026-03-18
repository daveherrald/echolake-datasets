# T1082-36: System Information Discovery — Display volume shadow copies with "vssadmin"

## Technique Context

T1082 System Information Discovery encompasses adversaries gathering information about the operating system and hardware configuration. Volume shadow copies (VSS) are point-in-time snapshots of disk volumes that Windows uses for backup and system restore functionality. Adversaries commonly enumerate shadow copies for two primary reasons: to identify backup data they can access for credential harvesting or data exfiltration, and to target shadow copies for deletion as part of ransomware operations (T1490). The `vssadmin list shadows` command is a standard Windows administrative tool that provides detailed information about existing shadow copies, including their creation time, volume location, and shadow copy ID. Detection teams focus on monitoring administrative shadow copy enumeration tools like vssadmin, wmic, and PowerShell VSS cmdlets, particularly when executed by non-administrative users or in unusual process contexts.

## What This Dataset Contains

This dataset captures a complete execution of `vssadmin list shadows` through PowerShell. The attack chain begins with PowerShell process creation (PID 9656) documented in Security EID 4688 events. The key command execution appears in Security event: `"cmd.exe" /c vssadmin.exe list shadows` (PID 38244), followed by the actual vssadmin execution: `vssadmin.exe list shadows` (PID 12604). Sysmon EID 1 events provide rich context, showing the full process lineage: powershell.exe → cmd.exe → vssadmin.exe, with the vssadmin process classified under the T1490 (Inhibit System Recovery) technique rule. The dataset includes extensive Sysmon EID 7 image load events showing .NET runtime libraries, Windows Defender integration (MpOAV.dll, MpClient.dll), and AMSI loading. Process access events (Sysmon EID 10) show PowerShell accessing both whoami.exe and cmd.exe child processes. Security EID 4703 events document privilege adjustments, including SeBackupPrivilege being enabled for both vssadmin.exe and the VSS service (VSSVC.exe). The Volume Shadow Copy service startup is captured with VSSVC.exe and supporting svchost.exe processes being created by services.exe.

## What This Dataset Does Not Contain

The dataset lacks the actual output of the vssadmin command - we see the process execution but not the enumerated shadow copy information that would be displayed to the attacker. No Sysmon ProcessCreate events exist for the main PowerShell processes due to the sysmon-modular config's include-mode filtering, though LOLBins like cmd.exe and vssadmin.exe are captured. The PowerShell channel contains only framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual PowerShell commands used to invoke the shadow copy enumeration. No network activity is present since this is purely local system information gathering. Registry access events that might show VSS configuration queries are absent. File access events to shadow copy metadata locations are not captured, limiting visibility into what shadow copy data the attacker might have discovered.

## Assessment

This dataset provides solid telemetry for detecting vssadmin-based shadow copy enumeration. The Security channel's command-line logging captures the exact command syntax, while Sysmon's process creation events with parent-child relationships clearly show the execution context. The privilege adjustment events (EID 4703) showing SeBackupPrivilege activation are particularly valuable for detection, as this privilege is commonly associated with backup/recovery operations that adversaries abuse. However, the lack of command output visibility limits the dataset's utility for understanding what information was actually gathered. The telemetry is sufficient for behavioral detection but insufficient for impact assessment. The presence of legitimate VSS service activation could create challenges for detection logic that doesn't account for normal administrative activity.

## Detection Opportunities Present in This Data

1. Monitor Security EID 4688 for vssadmin.exe execution with "list shadows" command line arguments, particularly when initiated by non-administrative tools or users
2. Detect Sysmon EID 1 process creation events for vssadmin.exe with T1490 technique classification, correlating with parent processes like cmd.exe or PowerShell
3. Alert on Security EID 4703 privilege adjustment events showing SeBackupPrivilege being enabled for vssadmin.exe processes, especially outside normal backup windows
4. Monitor process chains combining PowerShell → cmd.exe → vssadmin.exe execution patterns using Sysmon parent-child process relationships
5. Correlate vssadmin execution with subsequent VSS service (VSSVC.exe) startup events from Security EID 4688 to identify shadow copy enumeration activity
6. Track Security EID 4689 process termination events for short-lived vssadmin executions that may indicate automated reconnaissance scripts
7. Detect unusual process access patterns (Sysmon EID 10) where PowerShell accesses vssadmin or cmd.exe child processes with high privileges (0x1FFFFF access)
