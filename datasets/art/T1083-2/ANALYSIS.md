# T1083-2: File and Directory Discovery — PowerShell

## Technique Context

T1083 File and Directory Discovery is a fundamental reconnaissance technique where adversaries enumerate files and directories to understand the target environment and locate data of interest. This technique is particularly common during post-exploitation phases as attackers map out the file system to identify valuable files, user directories, configuration files, and potential lateral movement targets.

PowerShell-based file discovery is especially prevalent on Windows systems due to PowerShell's native file system navigation capabilities through cmdlets like `Get-ChildItem` (and its aliases `ls`, `gci`, `dir`). The detection community focuses heavily on monitoring PowerShell execution patterns, particularly recursive directory enumeration with the `-Recurse` parameter, as this often indicates systematic reconnaissance rather than normal administrative activity. Key detection indicators include PowerShell processes executing file system cmdlets with recursive flags, especially when originating from non-interactive contexts or spawning from suspicious parent processes.

## What This Dataset Contains

This dataset captures a straightforward PowerShell-based file discovery execution using multiple aliases for the same cmdlet. The technique executed three equivalent commands in sequence:

- Security Event 4688 shows the spawning of a child PowerShell process with the command line: `"powershell.exe" & {ls -recurse\nget-childitem -recurse\ngci -recurse}`
- PowerShell Event 4104 captured the script block: `& {ls -recurse\nget-childitem -recurse\ngci -recurse}`
- PowerShell Event 4103 logged the actual cmdlet invocation: `CommandInvocation(Get-ChildItem): "Get-ChildItem"` with `ParameterBinding(Get-ChildItem): name="Recurse"; value="True"`

The Sysmon ProcessCreate event (EID 1) captured the PowerShell process creation with RuleName `technique_id=T1083,technique_name=File and Directory Discovery`, demonstrating that the sysmon-modular configuration correctly identified this as file discovery activity. The process chain shows the parent PowerShell process (PID 14412) spawning the child PowerShell process (PID 6492) that performed the actual enumeration.

The dataset also includes ancillary telemetry: Sysmon EID 7 events showing .NET runtime DLL loading, Sysmon EID 17 events for named pipe creation during PowerShell initialization, and Sysmon EID 11 events showing PowerShell profile file creation.

## What This Dataset Does Not Contain

The dataset lacks the actual output or results of the file discovery operation. While we can see the PowerShell cmdlets were executed successfully (no error events present), we don't have telemetry showing which files and directories were enumerated, how many items were processed, or what specific paths were accessed. This is expected behavior as PowerShell logging typically captures command execution but not the detailed output unless specific transcription logging is configured differently.

The dataset also doesn't contain any file access events (Security EID 4656/4658) that might show granular file system access patterns during the enumeration, likely because object access auditing is disabled in the audit policy configuration. No network activity is present, indicating this was purely local file system discovery rather than remote enumeration.

## Assessment

This dataset provides excellent telemetry for detecting PowerShell-based file discovery operations. The combination of Security EID 4688 process creation events with full command-line logging, PowerShell EIDs 4103/4104 for cmdlet execution and script block logging, and Sysmon EID 1 process creation with technique-specific rule matching creates multiple overlapping detection opportunities. 

The data quality is strong for detection engineering purposes, showing clear execution of the Get-ChildItem cmdlet with the `-Recurse` parameter across multiple data sources. The presence of both the parent process context and the specific PowerShell cmdlet parameters provides sufficient detail for building robust detection logic.

The main limitation is the absence of file access telemetry that could help distinguish between broad reconnaissance scanning versus targeted file searches, but this is a configuration choice rather than a data quality issue.

## Detection Opportunities Present in This Data

1. **PowerShell Process Creation with File Discovery Commands** - Security EID 4688 events showing powershell.exe processes with command lines containing "get-childitem", "ls", or "gci" combined with "-recurse" parameters.

2. **PowerShell Script Block Logging for Recursive Directory Enumeration** - PowerShell EID 4104 events containing script blocks with Get-ChildItem cmdlets and recursive flags, particularly when executed in scriptblock format.

3. **PowerShell Cmdlet Invocation Monitoring** - PowerShell EID 4103 events showing CommandInvocation for Get-ChildItem with ParameterBinding indicating Recurse=True.

4. **Sysmon Process Creation with Technique Classification** - Sysmon EID 1 events with RuleName containing "technique_id=T1083" indicating file discovery activity, especially useful for automated alerting.

5. **Process Chain Analysis for Discovery Context** - Correlating parent-child process relationships where PowerShell processes spawn additional PowerShell instances specifically for file enumeration tasks.

6. **Multi-Alias Discovery Command Detection** - Identifying the use of multiple aliases (ls, get-childitem, gci) for the same operation within a single execution, which may indicate evasion attempts or automated tool usage.
