# T1070.006-7: Timestomp — Windows - Modify file last access timestamp with PowerShell

## Technique Context

T1070.006 (Timestomp) is a defense evasion technique where attackers modify file timestamps to hide their activity, blend in with legitimate files, or interfere with forensic analysis. The detection community focuses on unusual timestamp modifications, especially those that set timestamps to suspicious values (Unix epoch, far future dates, or timestamps that predate file system creation). PowerShell-based timestomping is particularly common because it provides easy access to .NET file system objects and their timestamp properties. This technique is often used after malware deployment or data exfiltration to mask the timeline of malicious activity.

## What This Dataset Contains

This dataset captures a PowerShell-based timestamp modification technique that successfully executes. The core activity appears in Security 4688 events showing the process creation with the full command line: `"powershell.exe" & {Get-ChildItem \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1551.006_timestomp.txt\" | % { $_.LastAccessTime = \"01/01/1970 00:00:00\" }}`. This command modifies the LastAccessTime property of a target file to the Unix epoch (January 1, 1970).

The PowerShell script block logging in event 4104 captures the actual timestomping code: `& {Get-ChildItem "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1551.006_timestomp.txt" | % { $_.LastAccessTime = "01/01/1970 00:00:00" }}`. Sysmon captures the process creation chain showing the parent PowerShell process (PID 10536) spawning the child PowerShell process (PID 10440) that performs the timestamp modification.

Windows Defender was active but did not block this technique, allowing it to complete successfully. The telemetry shows normal PowerShell initialization (loading .NET assemblies like mscorlib.dll, clr.dll, and System.Management.Automation.dll) and execution without any access denied errors.

## What This Dataset Does Not Contain

This dataset does not contain direct evidence of the timestamp modification itself — there are no Sysmon file modification events (EID 2) or Security object access events that would show the actual timestamp changes. The sysmon-modular configuration may not monitor file attribute changes, and the Windows audit policy shows object access auditing is disabled ("object_access: none").

The dataset lacks any filesystem-level evidence that the timestamp modification actually occurred. There are no events showing before/after timestamp values or file system metadata changes. Additionally, the technique targets a file in the ExternalPayloads directory, but we don't see any events related to that specific file being accessed or modified.

## Assessment

This dataset provides solid telemetry for detecting PowerShell-based timestomping attempts through process creation and script block logging. The Security 4688 events with command-line logging capture the full attack command, while PowerShell 4104 events preserve the script content. However, the dataset's utility is limited by the lack of file system modification evidence — you can detect the attempt but cannot confirm successful execution without additional data sources.

The data quality is good for behavioral detection but insufficient for forensic analysis of the actual timestamp changes. Enhanced logging with file system auditing or Sysmon file modification events would significantly strengthen detection capabilities.

## Detection Opportunities Present in This Data

1. PowerShell command line analysis in Security 4688 events for timestamp modification patterns like `.LastAccessTime =`, `.CreationTime =`, or `.LastWriteTime =`

2. PowerShell script block content analysis in event 4104 for file timestamp manipulation commands combined with suspicious timestamp values (Unix epoch, future dates)

3. Process creation patterns showing PowerShell spawning child PowerShell processes specifically for file attribute modification operations

4. PowerShell invocation of Get-ChildItem cmdlet combined with timestamp property assignments in the same script block

5. Detection of hardcoded suspicious timestamp values like "01/01/1970 00:00:00" in PowerShell command lines or script blocks

6. Parent-child process relationships where PowerShell processes are created specifically to execute timestamp modification commands

7. PowerShell module loading patterns combined with file system object manipulation, particularly when System.Management.Automation is loaded alongside timestamp modification commands
