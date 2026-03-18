# T1105-22: Ingress Tool Transfer — Printer Migration Command-Line Tool UNC share folder into a zip file

## Technique Context

T1105 (Ingress Tool Transfer) involves adversaries transferring tools or files from an external system into a compromised environment. The detection community typically focuses on unusual file transfer mechanisms, network connections to suspicious destinations, and the abuse of legitimate tools for data exfiltration or tool staging. This specific variant leverages PrintBrm.exe, the Windows Printer Migration command-line tool, which can create zip archives from UNC share contents — a creative abuse of legitimate administrative functionality for potential data staging or exfiltration.

PrintBrm.exe is a signed Microsoft utility designed for printer driver and configuration backup/migration. When used with the `-b` (backup) flag and a UNC path as the source, it can effectively zip up directory contents from network shares, making it an interesting vector for both ingress tool transfer and data collection activities.

## What This Dataset Contains

This dataset captures a successful execution of PrintBrm.exe used to create a zip archive from a UNC share. The key telemetry shows:

**Process execution chain from Security 4688 events:**
- PowerShell launches: `"cmd.exe" /c del %TEMP%\PrintBrm.zip >nul 2>&1 & C:\Windows\System32\spool\tools\PrintBrm.exe -b -d \\127.0.0.1\c$\AtomicRedTeam\atomics\T1105\src\ -f %TEMP%\PrintBrm.zip -O FORCE`
- PrintBrm.exe executes: `C:\Windows\System32\spool\tools\PrintBrm.exe -b -d \\127.0.0.1\c$\AtomicRedTeam\atomics\T1105\src\ -f C:\Windows\TEMP\PrintBrm.zip -O FORCE`
- PrintBrmEngine.exe spawns from svchost.exe: `C:\Windows\system32\spool\tools\PrintBrmEngine.exe -Embedding`

**File creation events from Sysmon EID 11:**
- `C:\Windows\Temp\PrintBrm.zip` created by PrintBrmEngine.exe
- Multiple temporary OPC files created during the archiving process
- Temporary file in SystemTemp directory

**Process relationships from Sysmon EID 1:**
- Clear parent-child relationship showing PowerShell → cmd.exe → PrintBrm.exe
- PrintBrmEngine.exe launched by svchost.exe (normal COM activation pattern)
- Process access events showing PowerShell accessing child processes

The dataset shows successful completion with all processes exiting cleanly (exit status 0x0).

## What This Dataset Does Not Contain

The dataset lacks several potentially valuable detection signals:

- **Network connection telemetry**: No Sysmon EID 3 events showing the UNC share access (127.0.0.1 loopback connection may not trigger network logging)
- **File system access details**: No detailed file read operations from the source UNC path
- **Archive contents**: No visibility into what files were actually packaged into the zip
- **DNS queries**: No Sysmon EID 22 events (though this uses IP addressing)
- **Process command line details for PrintBrmEngine**: Limited visibility into the actual archiving operations

The sysmon-modular configuration's include-mode filtering for ProcessCreate explains why we see PrintBrm.exe and related processes but might miss other spawned utilities.

## Assessment

This dataset provides excellent telemetry for detecting PrintBrm.exe abuse for ingress tool transfer. The combination of Security 4688 command-line logging and Sysmon file creation events creates a comprehensive detection opportunity. The process chain is clear and the file artifacts are well-documented. However, the lack of network telemetry for the UNC share access represents a gap that could be addressed with additional network monitoring. The dataset effectively demonstrates how legitimate Windows utilities can be abused for data transfer operations while generating detectable artifacts.

## Detection Opportunities Present in This Data

1. **PrintBrm.exe command-line analysis** - Security EID 4688 showing PrintBrm.exe with `-b` (backup) flag and UNC path parameters, especially when the UNC path points to non-standard locations
2. **Unusual PrintBrm.exe execution context** - PrintBrm.exe spawned from cmd.exe or PowerShell rather than typical administrative tools
3. **Zip file creation in temporary directories** - Sysmon EID 11 showing PrintBrm.zip creation in %TEMP% or other suspicious locations
4. **PrintBrmEngine.exe COM activation patterns** - Detecting when PrintBrmEngine.exe is launched for non-standard backup operations
5. **Process access patterns** - Sysmon EID 10 showing PowerShell accessing PrintBrm.exe processes, indicating potential automation
6. **Command-line obfuscation detection** - The use of cmd.exe with chained commands and redirection could indicate attempt to hide activity
7. **UNC path analysis** - Detecting PrintBrm.exe accessing unusual network paths, especially localhost or internal IP addresses
8. **Temporary OPC file creation patterns** - Multiple temporary files in OPC directories during non-standard PrintBrm operations
