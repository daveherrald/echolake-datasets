# T1070.004-4: File Deletion — Delete a single file - Windows cmd

## Technique Context

T1070.004 File Deletion is a defense evasion technique where adversaries delete files and folders to remove evidence of their activities. File deletion is fundamental to maintaining operational security, covering tracks, and preventing forensic analysis. Attackers commonly delete temporary files, logs, executables, or documents that could reveal their presence or methods.

The detection community focuses on monitoring file deletion patterns, especially for sensitive files, system logs, or files in unexpected locations. Key detection approaches include tracking process execution of deletion utilities (del, erase, rmdir), monitoring file system events for bulk deletions, and identifying deletion of security-relevant files. This technique is particularly challenging to detect when performed through legitimate system utilities like cmd.exe.

## What This Dataset Contains

This dataset captures a straightforward file deletion using Windows cmd.exe. The core technique execution appears in Security event 4688 showing process creation: `"cmd.exe" /c del /f %temp%\deleteme_T1551.004`. The command deletes a test file from the temporary directory using the `/f` flag to force deletion.

Sysmon provides complementary process creation telemetry in EID 1 showing the cmd.exe process with command line `"cmd.exe" /c del /f %%temp%%\deleteme_T1551.004` (note the double percent signs due to variable expansion). The process chain shows PowerShell (PID 6344) spawning cmd.exe (PID 7052) for the deletion operation.

The dataset includes typical PowerShell test framework activity (Set-ExecutionPolicy Bypass commands in EIDs 4103/4104) and process access events (Sysmon EID 10) showing PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF). Security events capture process termination (EID 4689) for all spawned processes with clean exit status (0x0).

## What This Dataset Does Not Contain

This dataset lacks the actual file system evidence of the deletion operation itself. There are no Sysmon EID 23 (FileDelete) events showing the target file being removed, likely because the sysmon-modular configuration doesn't monitor file deletions in the temporary directory or the target file didn't exist.

The dataset also lacks any file creation events for the target file `deleteme_T1551.004`, suggesting this test may have attempted to delete a non-existent file. This is a common limitation in synthetic testing environments where setup steps may not create the expected target files.

Process access monitoring captured the cmd.exe execution but provides limited actionable intelligence about the specific files targeted for deletion.

## Assessment

This dataset provides solid process execution telemetry for cmd.exe-based file deletion but limited evidence of the actual deletion activity. The Security 4688 events with command-line logging capture the deletion command clearly, making this excellent data for building detections focused on process behavior rather than file system changes.

The absence of file deletion events (Sysmon EID 23) significantly reduces the dataset's utility for comprehensive file deletion monitoring. However, the clean process execution chain and command-line visibility make it valuable for detecting suspicious deletion commands, especially when combined with process ancestry analysis.

The data quality is high for what it captures, with clear process relationships and command-line details that would support both signature-based and behavioral detection approaches.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection** - Monitor Security 4688 events for `cmd.exe` processes with `/c del` or `/c erase` parameters, particularly with force flags (`/f`, `/q`)

2. **Process ancestry analysis** - Detect PowerShell spawning cmd.exe for file deletion operations, especially when combined with suspicious parent process characteristics

3. **Temporary file deletion monitoring** - Alert on deletion commands targeting `%temp%` or `%tmp%` directories, which may indicate cleanup of malicious artifacts

4. **Bulk deletion detection** - Look for rapid succession of cmd.exe processes performing deletion operations within short time windows

5. **Privilege escalation correlation** - Correlate file deletion activities with privilege adjustment events (Security 4703) showing elevated token rights

6. **Process access pattern analysis** - Monitor Sysmon EID 10 events showing processes accessing cmd.exe with full rights (0x1FFFFF) as potential indicators of process manipulation

7. **Cleanup behavior detection** - Identify file deletion commands executed shortly after other suspicious activities as potential evidence removal
