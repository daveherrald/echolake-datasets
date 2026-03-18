# T1036.003-8: Rename Legitimate Utilities — Malicious process Masquerading as LSM.exe

## Technique Context

T1036.003 (Rename Legitimate Utilities) is a defense evasion technique where adversaries copy legitimate utilities to different names or locations to masquerade as trusted processes. This specific test simulates copying cmd.exe to `lsm.exe` — mimicking the Local Session Manager service name to appear benign to security tools and analysts. The detection community focuses on identifying processes with suspicious names that don't match their file metadata, processes running from unusual locations, or legitimate utilities executing with renamed binaries. This technique is particularly effective because it leverages trust in legitimate process names while maintaining the original binary's functionality.

## What This Dataset Contains

This dataset captures a straightforward masquerading attempt where PowerShell executes a command chain to copy cmd.exe and run it as lsm.exe:

**Primary Command Execution (Security 4688):**
- PowerShell executes: `"cmd.exe" /c copy C:\Windows\System32\cmd.exe C:\lsm.exe & C:\lsm.exe /c echo T1036.003 > C:\T1036.003.txt`
- The masqueraded process executes: `C:\lsm.exe  /c echo T1036.003`

**Process Chain (Sysmon EID 1):**
- whoami.exe execution captured (PID 460, PPID 7352)
- cmd.exe execution captured (PID 6368, PPID 7352) with full copy/execute command
- **lsm.exe execution captured (PID 6328, PPID 6368)** — this is the masqueraded process

**File Operations (Sysmon EID 11):**
- File creation event shows: `C:\lsm.exe` created by cmd.exe (PID 6368)

**Key Detection Indicators:**
- The renamed binary retains original file metadata: `Description: Windows Command Processor`, `OriginalFileName: Cmd.Exe`
- Process name `lsm.exe` conflicts with legitimate Windows service naming conventions
- Execution from C:\ root instead of typical system directories

## What This Dataset Does Not Contain

This dataset lacks several valuable detection data points:
- **No Sysmon ProcessCreate events for PowerShell processes** due to include-mode filtering (PowerShell isn't in the suspicious patterns list)
- **No file copy operation details** — Sysmon didn't capture the actual copy operation, only the target file creation
- **No network activity** as this is a local masquerading test
- **No registry modifications** since cmd.exe doesn't require registry changes for basic functionality
- **Limited PowerShell telemetry** — only contains test framework boilerplate (Set-ExecutionPolicy) rather than the actual technique commands

## Assessment

This dataset provides solid process execution and file creation telemetry for detecting renamed utilities, but has gaps in showing the complete attack chain. The Security 4688 events with command-line logging are the strongest detection source here, capturing both the copy operation and the masqueraded execution. Sysmon EID 1 events are excellent for detecting the metadata mismatch (process name vs. OriginalFileName). However, the missing PowerShell ProcessCreate events and copy operation details limit the ability to build comprehensive detections for the full technique. The telemetry quality is good for endpoint detection but would benefit from broader process creation coverage.

## Detection Opportunities Present in This Data

1. **Process metadata mismatch detection** — Alert on processes where the executable name doesn't match the OriginalFileName field (lsm.exe running with OriginalFileName: Cmd.Exe)

2. **Suspicious process names mimicking system services** — Flag processes named after legitimate Windows services (lsm.exe) executing from non-standard locations

3. **Command-line analysis for file copying and execution** — Detect command patterns containing copy operations followed by execution of the copied file

4. **Legitimate utilities in unusual locations** — Alert on cmd.exe, powershell.exe, or other system binaries executing from root directories or user-writable paths

5. **Parent-child process relationship anomalies** — Monitor for cmd.exe spawning processes with different names than expected system utilities

6. **File creation followed by immediate execution** — Correlate Sysmon EID 11 (file creation) with EID 1 (process creation) for the same filename within short time windows
