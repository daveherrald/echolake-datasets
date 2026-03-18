# T1083-5: File and Directory Discovery — Simulating MAZE Directory Enumeration

## Technique Context

File and Directory Discovery (T1083) is a fundamental discovery technique where adversaries enumerate file system contents to understand the environment, locate valuable data, and plan subsequent actions. This technique is ubiquitous across attack campaigns, from initial reconnaissance to pre-exfiltration staging. The MAZE ransomware specifically implemented systematic directory enumeration patterns that became a signature of their operations — recursively crawling user directories, common application folders, and system locations to build comprehensive file inventories before encryption and exfiltration. Detection engineers focus on identifying unusual PowerShell filesystem enumeration, recursive directory traversal patterns, and the creation of output files that aggregate discovery results.

## What This Dataset Contains

This dataset captures a PowerShell-based implementation of MAZE-style directory enumeration executing via Security EID 4688 with the full command line: `"powershell.exe" & {$folderarray = @("Desktop", "Downloads", "Documents", "AppData/Local", "AppData/Roaming")`. The PowerShell script systematically enumerates multiple filesystem locations including the system drive root (`$env:homedrive`), Program Files directories, and all user profile subdirectories. PowerShell EID 4103 events provide detailed visibility into each `Get-ChildItem` command execution with specific paths like `C:\Program Files`, `C:\Users\mm11711\AppData\Local`, and attempts to access machine account directories. The script outputs all results to `C:\Windows\TEMP\T1083Test5.txt` via `Out-File -append`, captured in Sysmon EID 11 file creation events. PowerShell EID 4104 script block logging captures the complete enumeration logic, showing the nested foreach loops that iterate through user directories and predefined folder arrays. Sysmon EID 1 process creation events show the parent-child relationship between the initial PowerShell process and the spawned enumeration process, while EID 10 process access events indicate cross-process interactions during execution.

## What This Dataset Does Not Contain

The dataset lacks file system access auditing (Security EID 4656/4658) that would show individual directory access attempts, limiting visibility to successful PowerShell commands rather than the underlying filesystem operations. Windows Defender appears fully active but doesn't block this technique, suggesting no attempt telemetry from endpoint protection. The PowerShell channel contains mostly test framework boilerplate scriptblocks rather than comprehensive logging of the malicious enumeration script components. Network-based indicators are absent since this is purely local filesystem discovery. Registry operations related to PowerShell execution policy changes are not visible in the dataset, and WMI activity (despite WmiPrvSE.exe creation) doesn't appear to be directly related to the enumeration technique.

## Assessment

This dataset provides excellent coverage of PowerShell-based file discovery techniques through multiple complementary data sources. The Security channel's command-line auditing captures the complete attack payload while PowerShell operational logs reveal the detailed execution flow and parameter binding for each enumeration command. Sysmon adds process lineage and file creation telemetry that's crucial for understanding the technique's full execution chain. The combination of process creation (Security EID 4688, Sysmon EID 1), detailed PowerShell command logging (EID 4103), and output file creation (Sysmon EID 11) creates a comprehensive detection surface. The presence of error conditions in PowerShell logs (attempts to access non-existent machine account directories) actually strengthens the dataset by showing realistic execution scenarios including failed access attempts.

## Detection Opportunities Present in This Data

1. **PowerShell filesystem enumeration with output redirection** — Security EID 4688 command lines containing `Get-ChildItem` patterns combined with `Out-File -append` to temporary files
2. **Systematic user directory traversal** — PowerShell EID 4103 showing sequential enumeration of standard user folders (Desktop, Downloads, Documents, AppData) across multiple user profiles  
3. **Multi-location filesystem reconnaissance** — Detection of PowerShell accessing program directories, system drive roots, and user profiles within a single execution context
4. **Temporary file aggregation patterns** — Sysmon EID 11 file creation in system temp directories (`C:\Windows\TEMP`) by PowerShell processes performing discovery activities
5. **Cross-user profile enumeration** — PowerShell EID 4103 events showing attempts to access directories across different user accounts in rapid succession
6. **PowerShell process spawning for filesystem tasks** — Sysmon EID 1 showing PowerShell child processes with command lines containing multiple filesystem enumeration commands
7. **Error-based reconnaissance detection** — PowerShell EID 4103 NonTerminatingError events indicating systematic probing of directories that may not exist
