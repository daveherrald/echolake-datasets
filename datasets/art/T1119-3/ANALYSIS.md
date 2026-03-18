# T1119-3: Automated Collection — Recon information for export with PowerShell

## Technique Context

T1119 Automated Collection represents adversaries using scripts or tools to systematically gather files and information of interest from compromised systems. This technique is fundamental to many adversary playbooks, particularly in the Collection tactic where attackers seek to consolidate data before exfiltration. Common implementations include PowerShell scripts that enumerate system information, network configurations, running processes, services, and environment variables.

The detection community focuses heavily on monitoring for bulk collection activities — multiple enumeration commands executed in sequence, creation of staging files containing system information, and automated tools that rapidly collect diverse data types. PowerShell-based collection is especially prevalent due to its native Windows integration and extensive system access capabilities.

## What This Dataset Contains

This dataset captures a PowerShell-based automated collection test that executed three reconnaissance commands in sequence. The key evidence includes:

**Security Event 4688** shows the main PowerShell process creation with command line: `"powershell.exe" & {Get-Service > $env:TEMP\T1119_1.txt Get-ChildItem Env: > $env:TEMP\T1119_2.txt Get-Process > $env:TEMP\T1119_3.txt}`

**PowerShell Events 4103/4104** contain detailed command invocations and script block logging:
- `CommandInvocation(Get-Service)` capturing service enumeration
- `CommandInvocation(Get-ChildItem): name="Path"; value="Env:"` showing environment variable collection
- `CommandInvocation(Get-Process)` documenting process enumeration
- Multiple `Out-File` parameter bindings showing data being written to `C:\Windows\TEMP\T1119_1.txt`, `T1119_2.txt`, and `T1119_3.txt`

**Sysmon Events** provide process creation visibility:
- **Event 1** captures PowerShell process creation (PID 23204) with the full automation command line
- **Event 1** shows whoami.exe execution (PID 23564) for user discovery
- **Events 10** document process access between PowerShell processes indicating parent-child relationships
- **Events 11** confirm file creation of all three output files: `T1119_1.txt`, `T1119_2.txt`, `T1119_3.txt`

The PowerShell logging shows extensive parameter binding details, including actual service names being written to T1119_1.txt and process names being written to T1119_3.txt.

## What This Dataset Does Not Contain

The dataset lacks several elements that would be present in more sophisticated collection scenarios:
- No network activity or data exfiltration attempts following collection
- No compression or archiving of collected files
- Missing file access events for the created output files (suggesting they weren't subsequently read or copied)
- No evidence of credential harvesting or registry enumeration
- The Sysmon ProcessCreate filtering means some child processes spawned by PowerShell cmdlets may not be captured

The PowerShell channel contains mostly test framework boilerplate in addition to the actual technique execution, which is typical for these test environments.

## Assessment

This dataset provides excellent coverage for detecting automated PowerShell-based collection activities. The combination of Security 4688 events with full command lines, comprehensive PowerShell 4103/4104 logging with parameter binding details, and Sysmon file creation events creates multiple detection opportunities. The data quality is high for this technique since PowerShell-based collection generates rich telemetry across multiple log sources.

The main limitation is that this represents a basic collection pattern — more advanced automated collection might involve encrypted staging, remote execution, or steganographic techniques that would generate different telemetry patterns.

## Detection Opportunities Present in This Data

1. **Multiple enumeration commands in single PowerShell execution** - Detect command lines containing multiple system enumeration cmdlets (Get-Service, Get-Process, Get-ChildItem Env:) executed together
2. **Sequential file creation in temp directories** - Alert on rapid creation of multiple files in %TEMP% or similar staging locations by the same process
3. **PowerShell parameter binding patterns** - Monitor for Out-File cmdlet usage with multiple temporary file targets containing system information
4. **Automated collection script blocks** - Detect PowerShell script blocks containing multiple enumeration cmdlets with output redirection operators
5. **Process enumeration combined with service discovery** - Flag PowerShell sessions executing both Get-Process and Get-Service within short timeframes
6. **Environment variable collection** - Monitor for Get-ChildItem usage targeting the Env: provider, especially when combined with other enumeration
7. **Bulk system information gathering** - Correlate multiple PowerShell CommandInvocation events for reconnaissance cmdlets within the same session
8. **Temporary file staging patterns** - Detect file creation events for multiple .txt files in system temp directories with reconnaissance-related naming patterns
