# T1070.006-5: Timestomp — Windows - Modify file creation timestamp with PowerShell

## Technique Context

T1070.006 (Timestomp) is a defense evasion technique where attackers modify file timestamps to avoid detection and blend in with legitimate file activity. The technique is particularly valuable for hiding evidence of file system modifications, making malicious files appear older or newer than they actually are, and potentially evading timeline-based forensic analysis.

This specific test demonstrates PowerShell-based timestomping, which is commonly used by attackers because PowerShell provides direct access to .NET file system objects and their timestamp properties. The detection community focuses on monitoring file timestamp modifications, especially when timestamps are set to suspicious values (like Unix epoch times or significantly backdated timestamps), and PowerShell commands that interact with file system metadata.

## What This Dataset Contains

The dataset captures a PowerShell-based timestomping operation targeting the file `C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1551.006_timestomp.txt`. The core technique evidence appears in:

**Security Event 4688** showing the PowerShell command execution:
```
Process Command Line: "powershell.exe" & {Get-ChildItem \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1551.006_timestomp.txt\" | % { $_.CreationTime = \"01/01/1970 00:00:00\" }}
```

**PowerShell Event 4104** capturing the actual timestomping script blocks:
```
& {Get-ChildItem "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1551.006_timestomp.txt" | % { $_.CreationTime = "01/01/1970 00:00:00" }}
```

**Sysmon Event 1** showing the PowerShell process creation with the full command line that modifies the file creation timestamp to January 1, 1970 (Unix epoch).

The dataset includes complete process creation telemetry, PowerShell script block logging, and normal PowerShell startup activities. Both the parent PowerShell process (PID 27624) and child PowerShell process (PID 43168) are captured with their respective process access events (Sysmon EID 10).

## What This Dataset Does Not Contain

The dataset lacks file system monitoring events that would directly show the timestamp modification occurring. Sysmon EID 2 (File creation time changed) events are not present, which would be the most direct evidence of timestomping activity. This absence suggests the sysmon-modular configuration may not include file timestamp change monitoring, or the specific file modification didn't trigger the expected events.

The dataset also doesn't contain any Windows Defender blocking or quarantine events, indicating the timestomping operation completed successfully. There are no USN journal entries or other file system audit events that would show the actual timestamp changes taking effect.

## Assessment

This dataset provides solid detection opportunities through command-line and PowerShell script block logging, but lacks the direct file system evidence of timestamp modification. The Security EID 4688 and PowerShell EID 4104 events contain excellent behavioral indicators, including the suspicious Unix epoch timestamp value and PowerShell file system manipulation patterns.

The telemetry is particularly strong for detecting PowerShell-based timestomping through process monitoring and script block analysis. However, defenders seeking to confirm the actual timestamp modification would need additional file system monitoring capabilities beyond what this dataset captures.

## Detection Opportunities Present in This Data

1. **PowerShell timestamp manipulation commands** - Monitor PowerShell EID 4104 script blocks containing `.CreationTime`, `.LastWriteTime`, or `.LastAccessTime` property assignments, especially with suspicious timestamp values

2. **Unix epoch timestamp indicators** - Alert on PowerShell commands setting file timestamps to "01/01/1970" or other historically significant dates that suggest timestamp manipulation

3. **PowerShell Get-ChildItem with timestamp modification** - Detect PowerShell command patterns combining `Get-ChildItem` with timestamp property modifications using pipelines and `%` (ForEach-Object alias)

4. **Suspicious file metadata manipulation** - Monitor Security EID 4688 process creation events for PowerShell command lines containing file timestamp manipulation syntax

5. **PowerShell file system object property access** - Create detection logic for PowerShell accessing `System.IO.FileInfo` timestamp properties through `.CreationTime`, `.LastWriteTime`, and `.LastAccessTime` assignments

6. **Process lineage analysis** - Track PowerShell parent-child relationships where child PowerShell processes execute file system manipulation commands, as shown in the process tree from this execution
