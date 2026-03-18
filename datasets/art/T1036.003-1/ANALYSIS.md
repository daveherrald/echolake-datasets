# T1036.003-1: Rename Legitimate Utilities — Masquerading as Windows LSASS process

## Technique Context

T1036.003 (Rename Legitimate Utilities) is a defense evasion technique where attackers copy legitimate system binaries to new locations with deceptive names to masquerade as different processes. This technique is commonly used to bypass basic process name-based detections and blend in with legitimate system activity. Attackers often target critical system process names like lsass.exe, svchost.exe, or winlogon.exe to make their malicious processes appear legitimate to both automated tools and human analysts.

The detection community focuses on identifying renamed binaries through several approaches: monitoring for unsigned binaries running from unusual locations with system process names, tracking file copy operations to sensitive directories, detecting process execution from non-standard paths, and analyzing metadata mismatches between process names and their actual binary origins.

## What This Dataset Contains

This dataset captures a successful execution of the rename masquerading technique with comprehensive telemetry:

**Process Chain**: PowerShell → cmd.exe → renamed lsass.exe (copied cmd.exe)
- Security 4688 shows the initial cmd.exe execution: `"cmd.exe" /c copy %SystemRoot%\System32\cmd.exe %SystemRoot%\Temp\lsass.exe & %SystemRoot%\Temp\lsass.exe /B`
- Sysmon EID 1 captures the cmd.exe process creation with full command line showing the copy and execution sequence
- Sysmon EID 11 documents the file creation: `C:\Windows\Temp\lsass.exe` created by cmd.exe
- Sysmon EID 1 shows the masquerading process execution: `C:\Windows\Temp\lsass.exe /B` with parent process cmd.exe
- Security 4688 confirms the renamed process execution with path `C:\Windows\Temp\lsass.exe`

**Key Evidence**:
- File hashes show the renamed lsass.exe is identical to cmd.exe: `SHA256=A6E3B3B22B7FE8CE2C9245816126723EAA13F43B9F591883E59959A2D409426A`
- Original filename metadata still shows "Cmd.Exe" despite being named lsass.exe
- Sysmon EID 7 shows the masquerading process loading itself: `ImageLoaded: C:\Windows\Temp\lsass.exe`
- Process executes from non-standard location (C:\Windows\Temp\ vs C:\Windows\System32\)
- Sysmon EID 5 captures clean termination of the masquerading process

## What This Dataset Does Not Contain

The dataset is complete for this technique execution. Windows Defender did not block the activity as this represents a legitimate binary (cmd.exe) being copied and executed, which is not inherently malicious. The technique executed successfully without generating any access denied errors or antivirus alerts. All expected events for file operations, process creation, and execution are present in the telemetry.

## Assessment

This dataset provides excellent coverage for detecting T1036.003 through multiple complementary data sources. Security 4688 events capture the full command line showing the copy operation and execution, while Sysmon EID 1, 11, and 7 provide detailed process creation, file creation, and image load events. The combination of process creation from unusual paths, file creation in temp directories with system process names, and metadata analysis opportunities makes this dataset highly valuable for detection engineering. The presence of both the preparation (copy command) and execution phases provides complete attack chain visibility.

## Detection Opportunities Present in This Data

1. **Suspicious Process Path Detection**: Monitor for critical system process names (lsass.exe) executing from non-standard locations like C:\Windows\Temp\ instead of C:\Windows\System32\

2. **File Creation in Temp with System Names**: Alert on Sysmon EID 11 file creation events where system-critical process names are created in temporary directories

3. **Metadata Mismatch Analysis**: Detect when OriginalFileName field differs from the actual process name (OriginalFileName: Cmd.Exe vs process name lsass.exe)

4. **Hash-Based Binary Identification**: Correlate file hashes to identify when known legitimate binaries are running under different names

5. **Command Line Copy Pattern Detection**: Monitor Security 4688 and Sysmon EID 1 for command patterns copying system binaries to alternate locations with deceptive names

6. **Parent-Child Process Anomalies**: Flag when cmd.exe creates processes with system-critical names in unusual directories

7. **Image Load from Unusual Paths**: Monitor Sysmon EID 7 for processes loading images from non-standard system directories with critical process names
