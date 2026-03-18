# T1070.004-11: File Deletion — Clears Recycle bin via rd

## Technique Context

T1070.004 File Deletion is a defense evasion technique where adversaries delete files and directories to remove evidence of their presence or hinder forensic analysis. The Windows Recycle Bin serves as a temporary storage location for deleted files, making it a target for adversaries seeking to permanently remove traces of their activities. The `rd` (remove directory) command with `/s /q` flags is a common method to forcibly delete the entire Recycle Bin directory structure, bypassing the normal deletion process that would preserve files in the bin. This technique is frequently observed in post-exploitation activities, data destruction campaigns, and anti-forensics operations. Detection engineers focus on monitoring command-line executions targeting system directories like `$RECYCLE.BIN`, unusual file deletion patterns, and processes with elevated privileges performing bulk deletions.

## What This Dataset Contains

The dataset captures a PowerShell-initiated execution of `rd /s /q %systemdrive%\$RECYCLE.BIN` to clear the Recycle Bin. Security event 4688 shows the critical command line: `"cmd.exe" /c rd /s /q %%systemdrive%%\$RECYCLE.BIN` executed by PowerShell process 34148. The process chain shows PowerShell (PID 34148) spawning cmd.exe (PID 33248) to execute the deletion command. Sysmon event 1 captures both the whoami.exe execution (`C:\Windows\system32\whoami.exe`) and the cmd.exe execution with the full command line showing the Recycle Bin targeting. The technique successfully completes as evidenced by cmd.exe exit status 0x0 in Security event 4689. Sysmon events 10 show PowerShell accessing both spawned processes with full access rights (0x1FFFFF). Multiple PowerShell events capture the execution environment setup, including Set-ExecutionPolicy bypass operations. The execution occurs under NT AUTHORITY\SYSTEM context with System integrity level, indicating elevated privileges necessary for system directory manipulation.

## What This Dataset Does Not Contain

The dataset lacks direct evidence of actual file deletions or Recycle Bin contents being removed. No Sysmon file deletion events (EID 23) are present, likely because the sysmon-modular configuration may not monitor system directory deletions or the Recycle Bin was already empty. File system audit events that would show the removal of specific files from `C:\$RECYCLE.BIN` are absent, as object access auditing was disabled in the audit policy. Network activity logs that might show data exfiltration before deletion are not captured. Registry modifications that could indicate attempts to disable Recycle Bin functionality are not present. The dataset doesn't include Windows Defender alerts or file system filter driver notifications that might trigger on bulk deletion activities. Process memory dumps or detailed API call traces that would show the underlying file system operations are not available.

## Assessment

This dataset provides solid detection opportunities for T1070.004 through command-line monitoring and process creation events. The Security 4688 events with full command-line logging offer the strongest detection signals, clearly showing the `rd /s /q` command targeting `$RECYCLE.BIN`. Sysmon process creation events complement this with detailed parent-child relationships and file hashes. However, the dataset's value is somewhat limited by the absence of actual file deletion telemetry, making it difficult to confirm the technique's success or measure its impact. The lack of file system monitoring reduces the ability to detect more sophisticated deletion methods or confirm whether files were actually present to be deleted. For comprehensive T1070.004 detection, this dataset would benefit from file system auditing, Sysmon file delete events, and potentially Windows Defender file system monitoring.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection** - Monitor Security 4688 events for cmd.exe executions containing "rd /s /q" combined with "$RECYCLE.BIN" or system drive paths

2. **Process tree analysis** - Detect PowerShell spawning cmd.exe with Recycle Bin deletion commands, using parent-child process relationships from Sysmon EID 1

3. **Elevated privilege deletion monitoring** - Alert on System-level processes executing bulk directory deletion commands against protected system locations

4. **PowerShell command execution correlation** - Combine PowerShell operational logs showing execution policy bypass with subsequent file deletion commands

5. **Process access pattern detection** - Monitor Sysmon EID 10 events showing PowerShell accessing cmd.exe processes with full access rights (0x1FFFFF) followed by deletion commands

6. **System directory targeting** - Create rules for any process attempting to delete or modify contents of `%systemdrive%\$RECYCLE.BIN` regardless of method

7. **Execution context anomaly detection** - Flag unusual parent processes (like PowerShell) executing system maintenance commands typically run by administrative tools
