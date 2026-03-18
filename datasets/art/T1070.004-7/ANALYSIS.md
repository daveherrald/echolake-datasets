# T1070.004-7: File Deletion — Delete an entire folder - Windows PowerShell

## Technique Context

T1070.004 (File and Directory Deletion) is a defense evasion technique where adversaries delete files and directories to remove evidence of their activities or to prevent recovery of sensitive information. File deletion is one of the most fundamental anti-forensic techniques, commonly used by ransomware, APTs, and commodity malware to cover tracks. The detection community focuses on monitoring for bulk file deletions, deletions of security logs, system files, or forensically valuable artifacts, and unusual deletion patterns that deviate from normal user behavior. PowerShell's Remove-Item cmdlet with the -Recurse parameter is particularly noteworthy as it can delete entire directory trees in a single command, making it attractive for both legitimate administration and malicious cleanup activities.

## What This Dataset Contains

This dataset captures a PowerShell-based folder deletion attempt that ultimately fails because the target folder doesn't exist. The key evidence appears in multiple channels:

The Security channel shows the process creation chain: Security EID 4688 captures the PowerShell process creation with command line `"powershell.exe" & {Remove-Item -Path $env:TEMP\deleteme_folder_T1551.004 -Recurse}`. This provides clear visibility into the deletion attempt with the full command syntax.

The PowerShell channel contains the most detailed technique evidence. PowerShell EID 4103 shows the actual cmdlet invocation: `CommandInvocation(Remove-Item): "Remove-Item" ParameterBinding(Remove-Item): name="Path"; value="C:\Windows\TEMP\deleteme_folder_T1551.004" ParameterBinding(Remove-Item): name="Recurse"; value="True"` followed by the error `NonTerminatingError(Remove-Item): "Cannot find path 'C:\Windows\TEMP\deleteme_folder_T1551.004' because it does not exist."` PowerShell EID 4104 script block logging captures the actual command: `& {Remove-Item -Path $env:TEMP\deleteme_folder_T1551.004 -Recurse}`.

Sysmon provides process-level context through EID 1 events showing the PowerShell process creation with the full command line, though the parent PowerShell process (PID 30412) is not captured in Sysmon due to the include-mode filtering that only captures suspicious process patterns.

## What This Dataset Does Not Contain

This dataset doesn't contain evidence of successful file deletion because the target folder doesn't exist. There are no Sysmon EID 23 (FileDelete) events that would typically accompany successful folder deletion operations. The dataset lacks any file system modification evidence since the deletion command failed.

The Sysmon ProcessCreate events are incomplete due to the sysmon-modular configuration using include-mode filtering. The parent PowerShell process that spawned the deletion command is not captured in Sysmon EID 1 events, though it is visible in Security 4688 events. 

No file access or enumeration events precede the deletion attempt, which might be expected in real-world scenarios where attackers first identify target files before deletion. The technique execution is also quite artificial - the test attempts to delete a non-existent folder, so we don't see the forensic artifacts that would result from actual file system modifications.

## Assessment

This dataset provides excellent visibility into PowerShell-based file deletion attempts through multiple complementary data sources. The PowerShell operational logs offer the highest fidelity detection opportunities with both command invocation details and script block content. Security 4688 events with command-line logging provide reliable process-level visibility that survives even when PowerShell logging is disabled.

The failure condition actually enhances the dataset's value for detection engineering by showing how error conditions appear in the logs - the PowerShell NonTerminatingError provides clear evidence of deletion attempts even when they fail. For building robust detections, this demonstrates that monitoring for both successful and failed deletion operations can provide comprehensive coverage.

## Detection Opportunities Present in This Data

1. **PowerShell Remove-Item with Recurse parameter detection** - Monitor PowerShell EID 4103 CommandInvocation events for Remove-Item cmdlet with Recurse parameter binding, indicating bulk deletion attempts.

2. **Script block analysis for file deletion patterns** - Detect PowerShell EID 4104 script blocks containing Remove-Item commands with wildcard paths or environment variable expansion targeting common temporary directories.

3. **Process command-line monitoring for recursive deletion** - Alert on Security EID 4688 process creation events with command lines containing `Remove-Item.*-Recurse` or similar bulk deletion patterns.

4. **PowerShell deletion error analysis** - Monitor PowerShell EID 4103 NonTerminatingError events related to Remove-Item operations to detect failed cleanup attempts that may indicate incomplete anti-forensic activities.

5. **Environment variable path deletion detection** - Identify PowerShell commands targeting deletion of paths using environment variables like `$env:TEMP`, `$env:APPDATA`, or `$env:USERPROFILE` which are common cleanup targets.

6. **PowerShell pipe creation correlation** - Correlate Sysmon EID 17 pipe creation events with PowerShell deletion operations to identify scripted cleanup activities that may be part of larger attack chains.
