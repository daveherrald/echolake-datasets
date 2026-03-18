# T1218.001-5: Compiled HTML File — Invoke CHM Simulate Double click

## Technique Context

T1218.001 (Compiled HTML File) is a defense evasion technique where attackers abuse Microsoft's HTML Help (CHM) files to execute malicious code while bypassing application control mechanisms. CHM files are legitimate Microsoft Help file formats that can contain embedded scripts and executable content. When a CHM file is opened, it's processed by hh.exe (HTML Help Executable), which can execute JavaScript, VBScript, or other active content within the file.

The detection community focuses on monitoring hh.exe process creation, unusual CHM file access patterns, network connections from hh.exe, and the execution of child processes spawned by HTML Help files. This technique is particularly concerning because CHM files are often trusted file types that may bypass security controls, and they can be used to execute PowerShell, download additional payloads, or perform other malicious activities while appearing as legitimate help file access.

## What This Dataset Contains

This dataset captures telemetry from an Atomic Red Team test that simulates a user double-clicking a CHM file using the `Invoke-ATHCompiledHelp` PowerShell function. The key evidence includes:

**PowerShell Script Block Logging**: EID 4104 events show the execution of `Invoke-ATHCompiledHelp -SimulateUserDoubleClick -CHMFilePath Test.chm`, revealing the technique being simulated through PowerShell rather than an actual CHM file execution.

**Process Creation**: Security EID 4688 events capture the creation of a new PowerShell process with command line `"powershell.exe" & {Invoke-ATHCompiledHelp -SimulateUserDoubleClick -CHMFilePath Test.chm}`, and a whoami.exe process (`"C:\Windows\system32\whoami.exe"`).

**Sysmon Process Creation**: EID 1 events show both the whoami.exe execution (tagged as T1033 System Owner/User Discovery) and the second PowerShell process creation with the full command line containing the CHM simulation.

**Process Access**: Sysmon EID 10 events document PowerShell accessing both the whoami.exe and second PowerShell processes with full access rights (0x1FFFFF).

**File System Activity**: Sysmon EID 11 events capture PowerShell profile data file creation in the system profile directory.

## What This Dataset Does Not Contain

This dataset lacks the most critical telemetry expected from actual CHM file abuse. Notably absent is any execution of hh.exe (HTML Help Executable), which is the primary indicator of CHM file processing. There are no file creation events for an actual CHM file, no network connections from hh.exe, and no evidence of content extraction or JavaScript/VBScript execution within a CHM context.

The test appears to be a PowerShell simulation rather than actual CHM file execution, meaning the core behavioral indicators of T1218.001 are not present. Windows Defender's real-time protection may have prevented actual CHM file creation or execution, or the test framework may have chosen to simulate the technique rather than execute it directly.

## Assessment

This dataset provides limited value for building detections specific to T1218.001 (Compiled HTML File). While it captures the PowerShell-based simulation telemetry effectively, it lacks the fundamental behavioral evidence that characterizes actual CHM file abuse—specifically hh.exe execution and the associated file system and network activities.

The telemetry is more valuable for detecting PowerShell-based attack simulations and techniques that use PowerShell to mimic other attack vectors. The process creation, script block logging, and process access events provide good coverage of PowerShell activity, but miss the critical hh.exe behavioral patterns that defenders need to detect legitimate CHM file abuse.

## Detection Opportunities Present in This Data

1. **PowerShell CHM simulation detection**: Monitor PowerShell script blocks containing "Invoke-ATHCompiledHelp" or references to CHM file manipulation for potential testing or simulation activities.

2. **PowerShell process spawning pattern**: Detect PowerShell processes creating child PowerShell processes with command line arguments containing CHM-related functions or file references.

3. **Suspicious PowerShell command line patterns**: Alert on PowerShell command lines containing "SimulateUserDoubleClick" or other testing framework indicators that suggest attack simulation.

4. **Process access from PowerShell to system utilities**: Monitor for PowerShell processes accessing system discovery tools like whoami.exe with full access rights, which may indicate reconnaissance activities.

5. **PowerShell profile modification activity**: Track creation or modification of PowerShell startup profile data files that could indicate persistence mechanisms or environment preparation.

6. **Multi-stage PowerShell execution**: Detect patterns where PowerShell spawns additional PowerShell processes, particularly when combined with file manipulation or discovery commands.
