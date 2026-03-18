# T1005-1: Data from Local System — Search files of interest and save them to a single zip file (Windows)

## Technique Context

T1005 Data from Local System is a core Collection technique where adversaries gather files from the local file system before exfiltration. This technique is fundamental to data theft operations—attackers typically search for specific file types (documents, credentials, configuration files) based on extensions, keywords, or directory locations. The detection community focuses on identifying automated file enumeration patterns, especially recursive directory traversal combined with file filtering, and the subsequent staging of collected files into archives. PowerShell-based collection scripts are particularly common due to PowerShell's built-in file system and compression capabilities.

## What This Dataset Contains

This dataset captures a PowerShell-based data collection operation that searches for document files and archives them. The technique evidence spans multiple data sources:

**Security 4688 events** show the complete process execution chain, including the main PowerShell process (PID 0xa18/2584) with its full command line: `"powershell.exe" & {$startingDirectory = "C:\Users"... Compress-Archive -Path $foundFilePaths -DestinationPath "$outputZip\data.zip"`. The command line reveals the complete collection logic: targeting `.doc, .docx, .txt` files in `C:\Users`, using recursive enumeration with `Get-ChildItem -Recurse`, and creating a zip archive at `C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1005\data.zip`.

**PowerShell 4104 script block logging** captures the actual collection script execution in ScriptBlock ID `94b0022c-9fcf-4077-91a4-57530a8f5bd4`, showing the complete technique implementation including the custom `Search-Files` function and conditional archive creation logic.

**Sysmon events** provide detailed process telemetry with Sysmon 1 events for both whoami.exe (PID 2116) and the collection PowerShell process (PID 2584). Sysmon 10 process access events show PowerShell accessing both the whoami process and the collection process, and Sysmon 11 file creation events document PowerShell profile data files being created during execution.

## What This Dataset Does Not Contain

The dataset lacks file system enumeration details—there are no Sysmon 11 events showing the actual files being discovered during the `Get-ChildItem -Recurse` operation, nor file creation events for the final zip archive. This suggests either the collection found no matching files (likely given this is a test environment), or Sysmon's file creation monitoring may not capture all archive operations. The PowerShell channel contains primarily script block logging and test framework boilerplate rather than detailed cmdlet execution logs that would show the file discovery results.

## Assessment

This dataset provides excellent visibility into PowerShell-based data collection techniques. The Security 4688 events capture the complete attack methodology in the command line, while PowerShell script block logging preserves the actual malicious code. Sysmon adds valuable process relationship context. The main limitation is the absence of file system activity showing actual data collection results, but this doesn't diminish the dataset's value for detecting the collection attempt itself. The telemetry quality is strong for building detections around automated file enumeration patterns and archive creation behaviors.

## Detection Opportunities Present in This Data

1. **PowerShell recursive file enumeration** - Security 4688 command line contains `Get-ChildItem -Path $directory -File -Recurse` with file extension filtering
2. **File extension-based targeting** - Command line shows explicit targeting of document extensions `.doc, .docx, .txt` via string splitting and filtering
3. **Bulk file archiving behavior** - `Compress-Archive -Path $foundFilePaths` indicates staging collected files into a single archive
4. **Suspicious PowerShell script blocks** - PowerShell 4104 events capture the complete collection function implementation
5. **Directory traversal patterns** - Starting directory of `C:\Users` combined with recursive enumeration suggests user data targeting
6. **Archive staging to non-standard location** - Output path `C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1005\` indicates staging outside typical user directories
7. **PowerShell process spawning patterns** - Parent-child relationship between PowerShell processes for script execution
8. **Custom function definitions** - PowerShell script blocks show definition of `Search-Files` function for systematic file discovery
