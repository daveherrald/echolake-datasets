# T1218.001-1: Compiled HTML File — Compiled HTML Help Local Payload

## Technique Context

T1218.001 (Compiled HTML File) involves using Microsoft HTML Help (hh.exe) to execute arbitrary content through Compiled HTML Help (.chm) files. Attackers leverage this legitimate Windows utility to proxy execution of malicious code, bypassing application whitelisting and gaining initial code execution. The technique exploits the fact that hh.exe is a trusted Windows binary that can execute JavaScript, VBScript, or other active content embedded within CHM files.

The detection community focuses on monitoring hh.exe process creation with suspicious command lines, file system artifacts from CHM file processing, and child processes spawned from hh.exe that indicate payload execution. This technique is particularly valuable for attackers because hh.exe is rarely blocked by endpoint protection and provides a straightforward method for executing payloads delivered via phishing or other initial access vectors.

## What This Dataset Contains

This dataset captures a clean execution of the compiled HTML help technique with excellent process telemetry. The core attack chain is clearly visible in the Security and Sysmon logs:

Security EID 4688 shows the PowerShell-initiated process chain: `powershell.exe → cmd.exe → hh.exe` with the command line `"cmd.exe" /c hh.exe "C:\AtomicRedTeam\atomics\T1218.001\src\T1218.001.chm"`, followed by `hh.exe "C:\AtomicRedTeam\atomics\T1218.001\src\T1218.001.chm"`.

Sysmon EID 1 events provide detailed process creation telemetry including:
- `C:\Windows\System32\cmd.exe` (PID 18208) with CommandLine: `"cmd.exe" /c hh.exe "C:\AtomicRedTeam\atomics\T1218.001\src\T1218.001.chm"`
- `C:\Windows\hh.exe` (PID 15256) with CommandLine: `hh.exe "C:\AtomicRedTeam\atomics\T1218.001\src\T1218.001.chm"`

The Sysmon data includes process GUIDs, parent-child relationships, file hashes (SHA1=8E5F4A71774B6AF0ECFB81FFA9B29D2E8EFABE44), and integrity levels. The technique executed successfully with normal exit codes (exit status 0x0 for most processes, 0x1 for some cmd.exe instances indicating expected behavior).

## What This Dataset Does Not Contain

This dataset lacks the CHM file content analysis - we don't see what payload was embedded within the T1218.001.chm file or any subsequent execution artifacts from that payload. The Atomic Red Team test appears to use a benign CHM file that doesn't spawn additional malicious processes or perform typical post-exploitation activities.

There are no network connections initiated by hh.exe (no Sysmon EID 3 events), no file writes or modifications beyond normal system operations, and no registry modifications associated with the CHM execution. The PowerShell logs contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual technique implementation.

Windows Defender was active during execution but did not generate any blocking events, suggesting the test CHM file was benign or below detection thresholds.

## Assessment

This dataset provides excellent telemetry for detecting T1218.001 execution attempts. The process creation events from both Security 4688 and Sysmon EID 1 offer comprehensive coverage for building detections around hh.exe process spawning. The command-line logging captures the full execution context, and the parent-child process relationships are clearly preserved.

The main limitation is that this represents a sanitized test execution rather than real malicious activity, so it doesn't demonstrate the full attack lifecycle or defensive evasions that attackers might employ. However, the core behavioral patterns that detection engineers need to identify are well-represented.

## Detection Opportunities Present in This Data

1. **Process creation monitoring for hh.exe** - Sysmon EID 1 and Security EID 4688 events showing hh.exe spawning with .chm file arguments, particularly when originating from unusual parent processes

2. **Command-line analysis for CHM file execution** - Security EID 4688 events with command lines containing `hh.exe` followed by .chm file paths, especially from non-standard directories

3. **Parent-child process relationship analysis** - Sysmon EID 1 events showing cmd.exe or other processes spawning hh.exe, which may indicate scripted or automated execution

4. **File hash reputation checking** - Sysmon EID 1 provides hashes for hh.exe (SHA1=8E5F4A71774B6AF0ECFB81FFA9B29D2E8EFABE44) that can be validated against known-good baselines

5. **Process access monitoring** - Sysmon EID 10 events show PowerShell accessing spawned child processes, which may indicate process injection or monitoring attempts

6. **Execution from temporary directories** - Security EID 4688 shows processes running from C:\Windows\Temp\, which combined with hh.exe execution may indicate suspicious activity

7. **Time-based correlation** - Multiple rapid process creations involving hh.exe within short time windows may indicate automated or scripted attacks
