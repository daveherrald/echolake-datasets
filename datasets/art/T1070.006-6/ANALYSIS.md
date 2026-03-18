# T1070.006-6: Timestomp — Windows - Modify file last modified timestamp with PowerShell

## Technique Context

T1070.006 Timestomp is a defense evasion technique where adversaries modify file timestamps to hide malicious activity or blend in with legitimate files. By altering creation, modification, or access timestamps, attackers can evade timeline-based forensic analysis and detection mechanisms that rely on temporal patterns. PowerShell provides native capabilities for timestamp manipulation through objects like `Get-ChildItem` and direct property modification of file system objects.

The detection community focuses on monitoring file system metadata changes, particularly unusual timestamp patterns (files with ancient dates like 1970-01-01, or timestamps that don't align with system creation times), PowerShell commands that interact with file timestamp properties, and process execution patterns that suggest timestomping activities.

## What This Dataset Contains

This dataset captures a PowerShell-based timestomp operation targeting a test file. The core malicious activity is visible in Security event 4688, which shows the PowerShell command: `"powershell.exe" & {Get-ChildItem \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1551.006_timestomp.txt\" | % { $_.LastWriteTime = \"01/01/1970 00:00:00\" }}`.

PowerShell script block logging (event 4104) captures the actual timestomping command in ScriptBlock ID `93a875fa-b733-4b1d-8449-ed5a08b1e9a1`: `& {Get-ChildItem "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1551.006_timestomp.txt" | % { $_.LastWriteTime = "01/01/1970 00:00:00" }}`.

Sysmon process creation (event 1) shows the PowerShell child process with the full command line, including the classic Unix epoch timestamp of "01/01/1970 00:00:00" being applied to the target file. Process access events (Sysmon event 10) document the parent PowerShell process accessing the child PowerShell process with full access rights (0x1FFFFF).

The Security audit policy captures process creation and termination events (4688/4689) with command-line logging, providing complete visibility into the PowerShell execution chain. Security event 4703 shows privilege adjustment for the parent PowerShell process, including SeBackupPrivilege and SeRestorePrivilege which are relevant for file system operations.

## What This Dataset Does Not Contain

This dataset lacks the actual file system modification events that would show the timestamp change occurring. Windows doesn't generate audit events for metadata-only changes to file timestamps by default, requiring specialized auditing configurations or file system monitoring tools to capture these changes.

There are no Windows Defender alerts or blocks in this execution, as the timestomp operation completed successfully (all processes exit with status 0x0). Object access auditing is disabled in the environment, so we don't see file access events that might show the target file being opened or modified.

The technique executed successfully without generating error conditions or additional defensive responses, limiting the telemetry to process execution and PowerShell logging rather than defensive or filesystem change events.

## Assessment

This dataset provides good coverage of PowerShell-based timestomping through command-line auditing and PowerShell script block logging. The Security 4688 events with full command-line logging are particularly valuable, as they capture the complete attack command including the suspicious Unix epoch timestamp.

The PowerShell 4104 script block logging provides additional forensic value by capturing the exact script content being executed. However, the dataset would be significantly stronger with file system auditing enabled to capture the actual timestamp modifications, or with endpoint detection tools that monitor file metadata changes.

The process creation telemetry from both Security and Sysmon channels provides good process lineage tracking, though the core evidence relies heavily on command-line analysis rather than observing the actual file system changes.

## Detection Opportunities Present in This Data

1. **PowerShell timestomp command detection** - Security 4688 and PowerShell 4104 events containing PowerShell commands that modify `.LastWriteTime`, `.CreationTime`, or `.LastAccessTime` properties on file objects.

2. **Suspicious timestamp values** - Command lines containing historically significant dates like "01/01/1970 00:00:00" (Unix epoch), "01/01/1980", or other obviously fake timestamps that predate system installation.

3. **PowerShell file metadata manipulation** - Script blocks or command lines using `Get-ChildItem` combined with timestamp property assignments, particularly when targeting specific file paths.

4. **Process lineage for timestomping tools** - Parent-child relationships where PowerShell spawns with command lines containing file timestamp modification operations.

5. **Bulk timestamp modification patterns** - PowerShell commands using pipelines (`|`) and ForEach-Object (`%`) operators to modify timestamps across multiple files, indicating systematic timestomp operations.
