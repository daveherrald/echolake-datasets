# T1070.006-8: Timestomp — Windows - Timestomp a File

## Technique Context

T1070.006 (Timestomp) is a defense evasion technique where attackers modify file timestamps to hide evidence of their activities or blend malicious files with legitimate ones. Attackers commonly target the Modified, Accessed, Created, and Entry (MACE) timestamps visible in NTFS file systems. This technique is frequently used in post-exploitation phases to cover tracks, make forensic analysis more difficult, or help malicious files appear as if they were created at legitimate times. Detection engineers typically focus on monitoring file system APIs like SetFileTime, unusual timestamp patterns (files with identical or sequential timestamps, future dates, or timestamps that predate system installation), and the use of timestomping tools or PowerShell modules that manipulate file attributes.

## What This Dataset Contains

This dataset captures the execution of a PowerShell-based timestomping operation using a custom `timestomp.ps1` script. The key evidence appears in Security event 4688, which shows PowerShell launching with the command line: `"powershell.exe" & {import-module "C:\AtomicRedTeam\atomics\..\ExternalPayloads\timestomp.ps1" timestomp -dest "C:\AtomicRedTeam\atomics\..\ExternalPayloads\kxwn.lock"}`. 

The process chain shows an initial PowerShell process (PID 35200) that spawns whoami.exe (PID 38736) and then creates a second PowerShell process (PID 38908) to execute the timestomping operation. Sysmon captures extensive DLL loading events for both PowerShell processes, including .NET runtime components and Windows Defender integration modules. The PowerShell logging primarily contains test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) along with two script blocks showing the actual timestomp command: `import-module "C:\AtomicRedTeam\atomics\..\ExternalPayloads\timestomp.ps1"` and `timestomp -dest "C:\AtomicRedTeam\atomics\..\ExternalPayloads\kxwn.lock"`.

## What This Dataset Does Not Contain

The dataset lacks the most critical telemetry for detecting timestomping: file system modification events. There are no Sysmon Event ID 2 (File creation time changed) events that would directly indicate timestamp manipulation of the target file `kxwn.lock`. The Security channel also lacks any file system auditing events (4656, 4658, 4663) that would show access to or modification of the target file. Windows Defender appears to have allowed the operation to proceed (exit codes show 0x0 success), so there's no endpoint protection telemetry indicating the timestomping was blocked. The dataset also doesn't include any registry events that might show changes to file system metadata or any network events that could indicate the timestomp script was downloaded from a remote location.

## Assessment

This dataset provides limited value for building robust timestomping detections. While it captures the process execution and PowerShell command lines that could identify the use of timestomping tools, it fundamentally lacks the file system events that would confirm whether timestamp manipulation actually occurred. The most reliable detection opportunities are at the process and command line level rather than at the file system level where the actual technique takes place. For comprehensive timestomping detection, this dataset would need to be supplemented with file system auditing enabled and Sysmon configured to capture file creation time changes. The PowerShell logging does provide some value for detecting the use of specific timestomping modules, but many attackers use built-in Windows APIs rather than PowerShell scripts.

## Detection Opportunities Present in This Data

1. **PowerShell timestomping module usage** - Monitor for PowerShell script blocks or command lines containing "timestomp", "Set-FileTime", or similar timestamp manipulation functions from Security 4688 and PowerShell 4104 events.

2. **Suspicious PowerShell import-module patterns** - Detect PowerShell processes loading modules from non-standard paths like "ExternalPayloads" directories, which may indicate use of attack frameworks like Atomic Red Team.

3. **PowerShell child process spawning** - Monitor for PowerShell processes (Sysmon 1) that spawn additional PowerShell instances, which can indicate complex attack chains or evasion attempts.

4. **Process access patterns** - Correlate Sysmon 10 (Process Access) events showing PowerShell accessing other processes with subsequent file operations, which may indicate preparation for timestamp manipulation.

5. **Named pipe creation from PowerShell** - Monitor Sysmon 17 events for PowerShell creating named pipes with suspicious patterns like "PSHost" followed by multiple numeric identifiers, which can indicate automated or scripted execution.

6. **Command line reconstruction** - Combine Security 4688 process creation events with PowerShell 4104 script block logging to reconstruct the full attack chain and identify the specific files being targeted for timestamp manipulation.
