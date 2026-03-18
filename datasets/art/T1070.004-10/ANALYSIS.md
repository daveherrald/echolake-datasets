# T1070.004-10: File Deletion — Delete TeamViewer Log Files

## Technique Context

T1070.004 (File Deletion) is a defense evasion technique where adversaries delete files to cover their tracks and impede forensic analysis. This specific test targets TeamViewer log files, which are commonly deleted by attackers who have used TeamViewer for remote access to avoid leaving evidence of their sessions. TeamViewer logs contain connection details, user activities, and session timestamps that could reveal unauthorized access patterns. The detection community focuses on monitoring file deletion activities, especially for security-relevant log files, application logs, and files in temporary directories that might contain forensic artifacts.

## What This Dataset Contains

This dataset captures a PowerShell-based file deletion simulation where a TeamViewer log file is created and then immediately deleted. The core activity is visible in Security event 4688 showing the PowerShell command line: `"powershell.exe" & {New-Item -Path $env:TEMP\TeamViewer_54.log -Force | Out-Null Remove-Item $env:TEMP\TeamViewer_54.log -Force -ErrorAction Ignore}`.

Key telemetry includes:

**Sysmon Events:**
- EID 1: Process creation of powershell.exe with the full command line showing both file creation and deletion operations
- EID 1: Process creation of whoami.exe (likely test framework verification)
- EID 11: File creation event showing `C:\Windows\Temp\TeamViewer_54.log` being created at 18:45:28.143

**Security Events:**
- EID 4688: Process creation with complete command line showing the file manipulation commands

**PowerShell Events:**
- EID 4103: CommandInvocation events showing New-Item and Remove-Item cmdlet executions
- EID 4104: Script block logging capturing the file creation and deletion commands

The technique successfully creates a file at `C:\Windows\Temp\TeamViewer_54.log` (captured in Sysmon EID 11) and then deletes it using `Remove-Item` with `-Force` and `-ErrorAction Ignore` parameters.

## What This Dataset Does Not Contain

The dataset lacks a corresponding Sysmon file deletion event. While Sysmon EID 23 (FileDelete) events would normally capture file deletions, this specific deletion is not present in the telemetry. This could be due to the sysmon-modular configuration filtering certain file deletion events, the timing of the deletion happening too quickly after creation, or the specific path not being monitored for deletion events.

The dataset also doesn't contain any Windows Defender alerts or blocking events, indicating the simulated TeamViewer log deletion was not flagged as suspicious by the endpoint protection system.

## Assessment

This dataset provides good coverage for detecting file deletion techniques through process execution and PowerShell telemetry. The Security 4688 events with command-line logging and PowerShell operational logs (4103/4104) provide clear evidence of the deletion activity. However, the absence of Sysmon FileDelete events limits the ability to demonstrate file-system-level deletion detection. The data sources present are excellent for detecting PowerShell-based file manipulation and would support behavioral detections focusing on suspicious command patterns.

## Detection Opportunities Present in This Data

1. **PowerShell file deletion commands** - Monitor PowerShell EID 4103 CommandInvocation events for Remove-Item cmdlet usage, especially with Force parameter and ErrorAction Ignore
2. **Suspicious file creation/deletion patterns** - Correlate Sysmon EID 11 file creation events with PowerShell Remove-Item commands targeting the same file paths within short time windows
3. **TeamViewer log targeting** - Alert on file operations (creation, deletion, modification) targeting files with "TeamViewer" in the filename or path
4. **Process command line analysis** - Detect Security EID 4688 events where PowerShell command lines contain both New-Item and Remove-Item operations in sequence
5. **PowerShell script block content** - Monitor PowerShell EID 4104 script blocks containing file manipulation operations combined with error suppression flags
6. **Temporary directory file manipulation** - Flag file operations in %TEMP% directories, especially when involving log files or files with suspicious naming patterns
