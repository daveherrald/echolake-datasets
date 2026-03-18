# T1222.001-3: Windows File and Directory Permissions Modification — attrib - Remove read-only attribute

## Technique Context

T1222.001 (Windows File and Directory Permissions Modification) is a defense evasion technique where adversaries modify file or directory permissions to evade access controls or hide malicious activity. The `attrib` utility is a legitimate Windows tool commonly abused by attackers to modify file attributes, particularly to remove read-only flags that might prevent file modification or deletion. This technique is frequently observed in ransomware operations, data destruction scenarios, and when attackers need to modify protected system files or logs. Detection engineers focus on monitoring `attrib.exe` executions with suspicious parameters, especially bulk operations targeting multiple files or sensitive directories.

## What This Dataset Contains

This dataset captures a clean execution of the Atomic Red Team test that uses `attrib.exe` to remove read-only attributes from files. The key events show:

**Process Chain (Security 4688):**
- PowerShell (`powershell.exe`) spawns cmd.exe with command line: `"cmd.exe" /c attrib.exe -r %temp%\T1222.001_attrib\*.* /s`
- cmd.exe spawns attrib.exe with expanded command line: `attrib.exe -r C:\Windows\TEMP\T1222.001_attrib\*.* /s`

**Sysmon Process Creation (EID 1):**
- cmd.exe creation with CommandLine: `"cmd.exe" /c attrib.exe -r %%temp%%\T1222.001_attrib\*.* /s`
- attrib.exe creation with CommandLine: `attrib.exe -r C:\Windows\TEMP\T1222.001_attrib\*.* /s`

The technique successfully executed with all processes exiting cleanly (exit status 0x0). The attrib command targets files in `C:\Windows\TEMP\T1222.001_attrib\` with the `-r` flag to remove read-only attributes and `/s` for recursive operation.

## What This Dataset Does Not Contain

The dataset lacks several elements that would provide complete technique visibility:
- **File system events** showing actual attribute modifications - no Sysmon EID 2 (File creation time changed) or Windows Security file access auditing
- **Evidence of target files** - no indication whether files actually existed in the target directory or what attributes were modified
- **Registry events** - no Sysmon EID 12/13 showing potential registry attribute changes
- **Network activity** - no Sysmon EID 3 events indicating file access over network shares
- **Process termination timing** from Sysmon (only Security 4689 events present)

The missing file system audit trail means you cannot verify if the attrib operation actually modified any files or just attempted to do so against an empty directory.

## Assessment

This dataset provides solid process execution telemetry for detecting attrib.exe abuse but lacks the file system monitoring needed for complete technique coverage. The Security 4688 events with command-line logging offer excellent detection opportunities, while Sysmon EID 1 provides additional process context and hashes. The clean execution path makes this useful for testing detection logic, though the absence of file modification events limits its value for understanding the technique's impact. For production detection engineering, this data supports process-based detection rules but would need supplementation with file system auditing for comprehensive coverage.

## Detection Opportunities Present in This Data

1. **Attrib.exe execution with attribute modification flags** - Monitor Sysmon EID 1 and Security 4688 for `attrib.exe` with `-r`, `-h`, `-s`, or `+` parameters
2. **Bulk file operations via attrib** - Detect attrib.exe command lines containing wildcards (`*.*`) or recursive flags (`/s`)
3. **Command shell spawning attrib** - Alert on cmd.exe processes spawning attrib.exe, especially with suspicious parameters
4. **PowerShell invoking file attribute utilities** - Monitor PowerShell processes (Security 4688 Creator Process Name) spawning cmd.exe that subsequently runs attrib.exe
5. **Process ancestry chains involving LOLBins** - Track process trees where PowerShell → cmd.exe → attrib.exe with file modification parameters
6. **Temporary directory targeting** - Flag attrib operations against temp directories that may indicate cleanup or evasion activities
