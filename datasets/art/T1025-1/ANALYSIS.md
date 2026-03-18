# T1025-1: Data from Removable Media — Identify Documents on USB and Removable Media via PowerShell

## Technique Context

T1025 Data from Removable Media represents adversaries collecting data from removable storage devices like USB drives, external hard drives, optical discs, or memory cards. This technique is commonly used for data theft, lateral movement via infected removable media, or collection of sensitive documents that users might store on portable devices. Attackers often automate the discovery and collection process using scripts that enumerate removable drives and search for specific file types.

The detection community focuses on monitoring for systematic enumeration of removable drives, bulk file operations targeting document types, and PowerShell or command-line activities that interact with removable storage volumes. Key indicators include calls to storage management APIs, file system enumeration with specific extensions, and automated collection scripts.

## What This Dataset Contains

This dataset captures a PowerShell-based technique that searches for documents on removable media. The core activity is visible in Security event 4688 with the command line: `powershell.exe -c "Get-Volume | Where-Object {$_.DriveType -eq 'Removable'} | ForEach-Object { Get-ChildItem -Path ($_.DriveLetter + ':\*') -Recurse -Include '*.doc*','*.xls*','*.txt','*.pdf' -ErrorAction SilentlyContinue | ForEach-Object {Write-Output $_.FullName} } ; if (-not (Get-Volume | Where-Object {$_.DriveType -eq 'Removable'})) { Write-Output 'No removable media.' }"`.

The PowerShell script block logging (EID 4104) shows the actual script content: `Get-Volume | Where-Object {$_.DriveType -eq 'Removable'} | ForEach-Object { Get-ChildItem -Path ($_.DriveLetter + ':\*') -Recurse -Include '*.doc*','*.xls*','*.txt','*.pdf' -ErrorAction SilentlyContinue | ForEach-Object {Write-Output $_.FullName} } ; if (-not (Get-Volume | Where-Object {$_.DriveType -eq 'Removable'})) { Write-Output 'No removable media.' }`

PowerShell module logging (EID 4103) captures the execution of key cmdlets including `Get-Volume`, `Where-Object`, and `Write-Output`. The final Write-Output event shows the result: `Write-Output "No removable media."` indicating no removable drives were present on the test system.

The process chain visible in Sysmon EID 1 events shows: powershell.exe → cmd.exe → powershell.exe, with the nested PowerShell process (PID 1188) executing the removable media enumeration script. Sysmon EID 7 events capture .NET framework DLL loads and Windows Defender integration as the PowerShell processes initialize.

## What This Dataset Does Not Contain

The dataset doesn't contain actual removable media discovery or file collection since no removable drives were present during execution. There are no file access events (no Sysmon EID 15 ReadRawAccessRead events) or large-scale file enumeration patterns that would indicate successful data collection from removable storage.

The technique completed successfully but found no removable media, so we don't see the file system traversal, document discovery, or data staging activities that would occur if USB drives or other removable storage were connected to the system.

## Assessment

This dataset provides excellent telemetry for detecting T1025 reconnaissance activities. The PowerShell script block logging captures the complete technique implementation, while Security event 4688 provides reliable process creation visibility with full command lines. The combination of module logging and script block logging offers multiple detection layers.

The data sources are comprehensive for building detections around PowerShell-based removable media enumeration. However, the dataset's limitation is that it only captures the discovery phase without showing actual file collection activities that would occur when removable media is present.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Analysis** - EID 4104 contains the complete script searching for removable drives and specific file extensions (*.doc*, *.xls*, *.txt, *.pdf), providing high-fidelity detection content.

2. **Command Line Pattern Matching** - Security EID 4688 shows distinctive command line patterns including "Get-Volume", "DriveType -eq 'Removable'", and multiple document file extensions in a single command.

3. **PowerShell Module Usage Correlation** - EID 4103 events show sequential execution of Get-Volume, Where-Object filtering for removable drives, and conditional Write-Output activities.

4. **Process Chain Context** - Sysmon EID 1 events reveal the cmd.exe → powershell.exe execution pattern commonly used in automated data collection scripts.

5. **Storage Management API Usage** - PowerShell module logging captures interactions with Windows Storage Management APIs through Get-Volume cmdlet execution.

6. **File Extension Targeting** - The script specifically targets common document formats (DOC, XLS, TXT, PDF) which is characteristic of data collection operations rather than legitimate system administration.

7. **Bulk File Operation Indicators** - The use of Get-ChildItem with -Recurse and -Include parameters indicates systematic file system enumeration rather than targeted file access.
