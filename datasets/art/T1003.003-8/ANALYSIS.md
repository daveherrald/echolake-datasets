# T1003.003-8: NTDS — Create Symlink to Volume Shadow Copy

## Technique Context

T1003.003 (NTDS) involves extracting credential material from the Windows Active Directory database (ntds.dit) and related registry hives (SYSTEM, SECURITY, SAM). The specific test variant "Create Symlink to Volume Shadow Copy" represents a common approach where attackers create a volume shadow copy of the system drive using `vssadmin.exe`, then establish a symbolic link to access the shadow copy's protected files. This technique bypasses file system locks on active database files and is frequently observed in credential dumping operations by tools like secretsdump.py, ntdsutil, and manual extraction scripts. The detection community focuses on monitoring VSS operations combined with suspicious file access patterns, particularly when followed by registry hive or ntds.dit extraction.

## What This Dataset Contains

The dataset captures a complete volume shadow copy creation attempt. Security event 4688 shows PowerShell launching `cmd.exe` with the command line `"cmd.exe" /c vssadmin.exe create shadow /for=C: & mklink /D C:\Temp\vssstore \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1`, followed by vssadmin.exe execution with `vssadmin.exe create shadow /for=C:`. Sysmon EID 1 events capture the full process creation chain: powershell.exe → cmd.exe → vssadmin.exe. Security event 4703 shows privilege adjustments, including `SeBackupPrivilege` being enabled for vssadmin.exe, which is required for shadow copy operations. The vssadmin.exe process exits with status code 0x2, indicating an error condition. Multiple Sysmon EID 7 events show .NET runtime loading in PowerShell processes, and EID 10 process access events show PowerShell accessing child processes. Notably absent are any file creation events for the symbolic link or subsequent ntds.dit access attempts.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful shadow copy creation or symbolic link establishment. No Sysmon EID 11 file creation events show the creation of the symbolic link at `C:\Temp\vssstore`. There are no file access events indicating successful reading of ntds.dit, SYSTEM, or SECURITY hive files from the shadow copy. The vssadmin.exe exit status of 0x2 suggests the shadow copy creation failed, possibly due to insufficient privileges, VSS service issues, or Windows Defender interference. The PowerShell script block logging (EID 4104) contains only test framework boilerplate rather than the actual technique implementation. No registry access events or subsequent credential extraction activities are present.

## Assessment

This dataset provides excellent visibility into the process execution chain and privilege escalation patterns for VSS-based credential access attempts, but captures a failed execution. The Security channel with command-line logging provides comprehensive process lineage, while Sysmon EID 1 events offer detailed process creation telemetry with hashes and integrity levels. The 4703 privilege adjustment events are particularly valuable for detection, as `SeBackupPrivilege` elevation is a strong indicator of credential access preparation. However, the failure of the actual shadow copy creation limits the dataset's utility for understanding post-exploitation file access patterns. The data would be stronger with successful execution showing shadow copy creation, symbolic link establishment, and file access attempts.

## Detection Opportunities Present in This Data

1. **VSS Command Line Detection** - Monitor Security 4688 events for vssadmin.exe execution with "create shadow" parameters, particularly when spawned from scripting engines like PowerShell or cmd.exe

2. **Privilege Escalation Monitoring** - Detect Security 4703 events showing SeBackupPrivilege enablement for vssadmin.exe processes, which indicates preparation for shadow copy operations

3. **Suspicious Process Chain Analysis** - Alert on process lineage patterns of powershell.exe → cmd.exe → vssadmin.exe, especially when combined with shadow copy creation commands

4. **Shadow Copy Symbolic Link Detection** - Monitor for mklink commands in process command lines that reference GLOBALROOT device paths or HarddiskVolumeShadowCopy patterns

5. **Combined VSS and Link Creation** - Correlate vssadmin.exe shadow copy creation with subsequent mklink executions targeting shadow copy device paths within short time windows

6. **PowerShell Process Access Monitoring** - Use Sysmon EID 10 events to identify PowerShell processes accessing child processes with high privileges (0x1FFFFF), which may indicate process injection preparation
