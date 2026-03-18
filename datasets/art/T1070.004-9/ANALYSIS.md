# T1070.004-9: File Deletion — Delete Prefetch File

## Technique Context

T1070.004 (File Deletion) is a defense evasion technique where adversaries delete files to remove evidence of their activities or to hinder forensic analysis. Prefetch files (.pf) are a particularly valuable target because they contain execution artifacts that forensic analysts use to reconstruct program execution history. Windows automatically creates prefetch files in `C:\Windows\Prefetch\` to optimize application startup times, but these files also serve as forensic evidence showing when and how programs were executed.

The detection community focuses on monitoring file deletion operations in forensically significant directories, tracking PowerShell cmdlets like `Remove-Item`, and observing process access to prefetch directories. This technique is commonly used by attackers to clean up traces of their malicious activity, making it a high-value detection target.

## What This Dataset Contains

This dataset captures a PowerShell-based prefetch file deletion executed as NT AUTHORITY\SYSTEM. The core technique manifests in several key events:

**Security 4688 process creation** shows the PowerShell command line: `"powershell.exe" & {Remove-Item -Path (Join-Path ""$Env:SystemRoot\prefetch\"" (Get-ChildItem -Path ""$Env:SystemRoot\prefetch\*.pf"" -Name)[0])}`

**Sysmon Event 1** captures the same PowerShell process creation with additional forensic details including full file hashes and parent process information.

**PowerShell operational logging** provides granular visibility into the technique execution:
- EID 4103 CommandInvocation events show `Get-ChildItem` enumerating prefetch files with path `"C:\Windows\prefetch\*.pf"`
- EID 4103 Join-Path event reveals the target file: `"AM_DELTA.EXE-78CA83B0.pf"`
- EID 4103 Remove-Item event confirms deletion of `"C:\Windows\prefetch\AM_DELTA.EXE-78CA83B0.pf"`

**Process chain analysis** shows powershell.exe (PID 18264) spawning a child powershell.exe (PID 32400) to execute the deletion command, along with a whoami.exe execution for system reconnaissance.

## What This Dataset Does Not Contain

This dataset lacks several important telemetry sources for comprehensive file deletion detection:

**File system monitoring** - No Sysmon Event 23 (FileDelete) or Event 26 (FileDeleteDetected) events are present, likely because the sysmon-modular configuration doesn't monitor the prefetch directory for deletions.

**Object access auditing** - Security events for file access/deletion (4656/4658/4660/4663) are absent since object access auditing is disabled in the audit policy.

**ETW file system traces** - Advanced file system monitoring that could capture the actual file deletion at the kernel level is not available.

**Windows Defender intervention** - The prefetch deletion completed successfully (exit code 0x0), indicating Defender did not block this activity, which is expected since prefetch cleanup can be legitimate administrative behavior.

## Assessment

This dataset provides good process-level and PowerShell-level visibility into prefetch file deletion but lacks file system-level deletion events. The PowerShell operational logs are particularly valuable, offering complete command-line reconstruction and parameter binding details that clearly show the technique's execution flow. The Security 4688 events with command-line logging provide excellent detection opportunities for this technique.

However, the absence of actual file deletion events (Sysmon 23/26) limits forensic analysis capabilities. Detection engineers can build strong behavioral detections from the available process and PowerShell telemetry, but would need additional data sources for comprehensive file deletion monitoring.

## Detection Opportunities Present in This Data

1. **PowerShell Remove-Item targeting prefetch directory** - PowerShell 4103 events showing Remove-Item cmdlet with paths matching `*\prefetch\*.pf` pattern

2. **Process command line containing prefetch deletion logic** - Security 4688 or Sysmon 1 events with command lines containing both `Remove-Item`, `$Env:SystemRoot\prefetch`, and `.pf` patterns

3. **PowerShell enumeration of prefetch files** - PowerShell 4103 Get-ChildItem events with path parameters matching `*\prefetch\*.pf` followed by Remove-Item operations

4. **Suspicious PowerShell scriptblock creation** - PowerShell 4104 events containing prefetch deletion logic in scriptblock text

5. **Process access to system directories** - Sysmon 10 events showing PowerShell processes accessing other processes combined with file system operations in system directories

6. **Elevated PowerShell spawning child PowerShell for deletion** - Process creation chains showing powershell.exe spawning additional PowerShell instances with suspicious command lines targeting system forensic artifacts
