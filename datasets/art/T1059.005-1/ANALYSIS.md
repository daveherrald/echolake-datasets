# T1059.005-1: Visual Basic — Visual Basic script execution to gather local computer information

## Technique Context

T1059.005 covers the execution of Visual Basic scripts (VBScript) as a command and scripting interpreter. VBScript remains a powerful technique for adversaries due to its deep Windows integration, COM object access, and ability to perform system reconnaissance without additional tools. The detection community focuses heavily on cscript.exe/wscript.exe process creation patterns, script content analysis through AMSI, and the typical reconnaissance activities VBScript enables (WMI queries, file system enumeration, registry access). This particular test demonstrates a common reconnaissance pattern where VBScript gathers system information, which is fundamental tradecraft for establishing environmental context during initial access or post-exploitation phases.

## What This Dataset Contains

The dataset captures a complete VBScript execution chain initiated by PowerShell. Security event 4688 shows the process creation: `"C:\Windows\system32\cscript.exe" C:\AtomicRedTeam\atomics\T1059.005\src\sys_info.vbs`. Sysmon EID 1 provides additional detail with the same command line and full process genealogy showing `powershell.exe` as the parent process.

The VBScript execution involves significant DLL loading activity captured in Sysmon EID 7 events: `vbscript.dll` (the VBScript engine), `amsi.dll` (Anti-Malware Scan Interface), `wmiutils.dll` (indicating WMI usage for system information gathering), and Windows Defender components (`MpOAV.dll`). 

PowerShell script block logging (EID 4104) captures the exact invocation: `{cscript "C:\AtomicRedTeam\atomics\T1059.005\src\sys_info.vbs" > $env:TEMP\T1059.005.out.txt}`. Sysmon EID 11 shows file creation of `C:\Windows\Temp\T1059.005.out.txt`, confirming output redirection worked. Multiple Sysmon EID 10 process access events show PowerShell accessing both the `whoami.exe` and `cscript.exe` child processes with full access rights (0x1FFFFF).

The technique executed successfully with clean exit codes (Security EID 4689 shows exit status 0x0 for cscript.exe).

## What This Dataset Does Not Contain

The dataset lacks the actual VBScript content since it's stored in an external file (`sys_info.vbs`), limiting analysis of specific reconnaissance commands. While AMSI loaded into the cscript.exe process, no AMSI-related security events appear, suggesting the script content didn't trigger malware scanning alerts. The output file creation is captured but not the file contents, so we cannot observe what system information was actually collected. Network-based detection opportunities are absent as this was a local reconnaissance script with no network activity.

## Assessment

This dataset provides excellent telemetry for detecting VBScript execution with strong coverage across multiple event sources. The Security channel gives complete process lineage with command lines, Sysmon adds rich process creation details and file operations, and PowerShell logging captures the execution context. The DLL loading events are particularly valuable as they reveal the VBScript engine activation and WMI usage patterns. The combination of cscript.exe process creation, vbscript.dll loading, and file output creation provides multiple detection points with low false positive potential.

## Detection Opportunities Present in This Data

1. **VBScript Engine Process Creation** - Security EID 4688 and Sysmon EID 1 showing cscript.exe execution with .vbs file arguments
2. **VBScript DLL Loading Pattern** - Sysmon EID 7 showing vbscript.dll loaded into cscript.exe processes
3. **AMSI Integration Detection** - Sysmon EID 7 showing amsi.dll loading in script processes, indicating potential malware scanning opportunities
4. **WMI Reconnaissance Pattern** - Sysmon EID 7 showing wmiutils.dll loading, suggesting WMI-based system information gathering
5. **PowerShell-to-VBScript Execution Chain** - Security EID 4688 process genealogy showing powershell.exe spawning cscript.exe
6. **Script Output File Creation** - Sysmon EID 11 showing creation of temporary output files from script processes
7. **Cross-Process Access from PowerShell** - Sysmon EID 10 showing PowerShell accessing script processes with full permissions
8. **PowerShell Script Block Evidence** - PowerShell EID 4104 capturing the exact cscript invocation command
