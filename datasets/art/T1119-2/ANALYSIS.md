# T1119-2: Automated Collection — Automated Collection PowerShell

## Technique Context

T1119 Automated Collection represents adversaries using automated methods to gather files of interest based on specific criteria rather than relying on manual interaction. This technique is particularly relevant in data theft scenarios where attackers need to efficiently identify and collect documents, databases, or other sensitive files across large file systems. PowerShell-based automated collection is especially common in Windows environments due to PowerShell's powerful file system enumeration capabilities and its prevalence in legitimate administrative activities, making malicious usage blend into normal operations.

The detection community focuses on identifying suspicious PowerShell cmdlets for file enumeration (`Get-ChildItem`, `dir`, `ls`), filtering operations targeting specific file extensions, and bulk file operations (`Copy-Item`, `Move-Item`) that could indicate data collection activities. Key indicators include recursive directory searches, filtering by file extensions commonly associated with sensitive data (.doc, .pdf, .xls), and copying files to staging directories.

## What This Dataset Contains

This dataset captures a clean execution of PowerShell-based automated collection targeting `.doc` files. The core activity is visible in Security event 4688, which shows PowerShell spawning with the command line:

```
"powershell.exe" & {New-Item -Path $env:TEMP\T1119_powershell_collection -ItemType Directory -Force | Out-Null
Get-ChildItem -Recurse -Include *.doc | % {Copy-Item $_.FullName -destination $env:TEMP\T1119_powershell_collection}}
```

PowerShell logging provides detailed insight into the technique execution through events 4103 and 4104. Event 4103 captures command invocations for `New-Item` creating the staging directory `C:\Windows\TEMP\T1119_powershell_collection`, followed by `Get-ChildItem` with recursive search filtering for `*.doc` files, and `ForEach-Object` operations for copying discovered files.

Sysmon event 1 captures both the `whoami.exe` execution (process discovery) and the child PowerShell process creation for the collection operation. Event 11 shows the staging directory creation at `C:\Windows\Temp\T1119_powershell_collection`. Multiple Sysmon event 7s document .NET runtime loading and PowerShell automation assembly loading across the PowerShell processes. Event 10 shows process access from PowerShell to both `whoami.exe` and the child PowerShell process.

## What This Dataset Does Not Contain

The dataset does not contain evidence of any files actually being copied to the staging directory, suggesting either no `.doc` files were present on the system during execution or the search scope was limited. There are no Sysmon event 11 file creation events showing copied documents in the staging directory beyond the directory creation itself.

The PowerShell channel lacks the actual script block content that would show the full collection logic, instead containing mostly test framework-related script blocks (`Set-StrictMode`, error handling formatters) and the execution policy bypass. This limits visibility into the complete collection methodology.

Network-related events are absent, indicating this test focused purely on local file collection without any data exfiltration component. Additionally, there are no events showing cleanup activities removing the staging directory or collected files.

## Assessment

This dataset provides excellent telemetry for detecting PowerShell-based automated collection activities. The Security 4688 events with command-line logging capture the complete attack methodology, while PowerShell operational logging (4103/4104) provides detailed visibility into the specific cmdlets and parameters used. Sysmon process creation, file creation, and image load events offer complementary detection opportunities.

The data sources are particularly strong for this technique because automated collection fundamentally requires file system enumeration and bulk operations that generate significant audit trails. The combination of command-line arguments, PowerShell cmdlet invocations, and file system modifications creates multiple detection layers.

The main limitation is the apparent lack of actual file collection results, which reduces the dataset's utility for understanding post-collection behaviors like file compression, encryption, or staging for exfiltration.

## Detection Opportunities Present in This Data

1. **PowerShell Recursive File Search with Extension Filtering** - Security 4688 and PowerShell 4103 showing `Get-ChildItem -Recurse -Include *.doc` patterns targeting specific file types of interest

2. **Staging Directory Creation in Temporary Locations** - PowerShell 4103 `New-Item` operations creating directories with suspicious names (containing "collection", "gather", etc.) in `%TEMP%` or other staging locations

3. **Bulk File Copy Operations via PowerShell** - PowerShell 4103 `ForEach-Object` loops combined with `Copy-Item` cmdlets indicating systematic file collection rather than individual file access

4. **PowerShell Process Chains for Collection** - Sysmon 1 showing PowerShell spawning child PowerShell processes with file enumeration and copy operations in command lines

5. **File System Enumeration Followed by Staging** - Temporal correlation between `Get-ChildItem` operations and subsequent directory creation/file copy activities within short time windows

6. **PowerShell Execution Policy Bypass with Collection Activities** - PowerShell 4103 `Set-ExecutionPolicy Bypass` followed immediately by file enumeration and collection cmdlets
