# T1070.004-5: File Deletion — Delete an entire folder - Windows cmd

## Technique Context

T1070.004 File Deletion is a defense evasion technique where adversaries delete files and directories to remove evidence of their activities or to interfere with forensic analysis. This specific test demonstrates folder deletion using the Windows `rmdir` command, a common approach for removing entire directory structures that might contain artifacts from malicious activities. The detection community typically focuses on monitoring for bulk file deletion operations, deletion of security-relevant files and folders, and unusual deletion patterns that deviate from normal user behavior. This technique is frequently observed in ransomware cleanup operations, anti-forensics activities, and lateral movement cleanup phases.

## What This Dataset Contains

This dataset captures a PowerShell-initiated execution of `rmdir /s /q %temp%\deleteme_T1551.004` through cmd.exe. The Security 4688 event shows the core technique execution: `"cmd.exe" /c rmdir /s /q %%temp%%\deleteme_T1551.004`. The process chain is PowerShell (PID 27848) spawning cmd.exe (PID 27104), captured in both Security 4688 events and Sysmon EID 1 events. The cmd.exe process exits with status code 0x2, indicating the target folder likely didn't exist. Sysmon captures the full process creation chain with detailed command lines, while Security logs provide complementary process creation and termination events. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no technique-specific script blocks. Sysmon EID 10 events show PowerShell accessing both the whoami.exe and cmd.exe child processes with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

This dataset lacks the actual file system deletion events that would demonstrate successful technique execution. There are no Sysmon EID 23 (FileDelete) or EID 26 (FileDeleteDetected) events, which would be the primary indicators of actual file deletion activity. The cmd.exe exit status 0x2 suggests the target folder `%temp%\deleteme_T1551.004` didn't exist, so no deletion occurred. The dataset contains no file creation events showing the target folder being established before deletion. Windows file system audit events (Security 4656, 4658, 4660, 4663) are absent, which would provide additional deletion telemetry if object access auditing were enabled for the target directory.

## Assessment

This dataset provides limited value for T1070.004 detection engineering because the actual file deletion behavior didn't occur. While it captures the command-line patterns and process execution chains associated with folder deletion attempts, it lacks the file system events that would constitute successful technique execution. The Security 4688 and Sysmon EID 1 events do provide valuable command-line telemetry showing the `rmdir /s /q` syntax, which is useful for building process-based detections. However, for comprehensive T1070.004 coverage, analysts need datasets with successful deletions generating Sysmon EID 23/26 events or Windows file system audit logs. The current data is more suitable for detecting deletion attempts rather than successful deletions.

## Detection Opportunities Present in This Data

1. **Command Line Pattern Detection** - Security EID 4688 and Sysmon EID 1 capture `rmdir /s /q` command syntax, enabling detection of bulk directory deletion attempts regardless of success
2. **Process Chain Analysis** - PowerShell spawning cmd.exe with file deletion commands indicates potential defense evasion activity
3. **Suspicious Parent-Child Relationships** - PowerShell (scripting engine) launching cmd.exe with deletion parameters can indicate automated cleanup operations
4. **Command Parameter Analysis** - The `/s` (subdirectories) and `/q` (quiet mode) flags together suggest intentional bulk deletion with minimal user interaction
5. **Temp Directory Targeting** - Commands targeting `%temp%` directories may indicate cleanup of malicious artifacts or temporary files
6. **Process Access Monitoring** - Sysmon EID 10 events showing PowerShell accessing deletion processes with full rights could indicate process manipulation or monitoring
