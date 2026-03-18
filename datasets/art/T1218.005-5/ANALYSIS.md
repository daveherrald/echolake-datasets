# T1218.005-5: Mshta — Invoke HTML Application - Jscript Engine Simulating Double Click

## Technique Context

T1218.005 (Mshta) is a defense evasion technique where attackers abuse the Microsoft HTML Application Host (mshta.exe) to execute malicious code while bypassing application control mechanisms. Mshta.exe is a legitimate Windows utility that executes HTML Application (HTA) files containing embedded scripting languages like VBScript or JScript. This technique is particularly effective because mshta.exe is a signed Microsoft binary that security tools often trust by default.

Attackers commonly use mshta to execute remote HTA files via URLs, local HTA files dropped to disk, or inline script content passed directly as command-line arguments. The detection community focuses on monitoring mshta.exe process creation with suspicious command-line patterns, network connections to external resources, and child process spawning that indicates code execution beyond simple HTML rendering.

## What This Dataset Contains

This dataset captures an Atomic Red Team test that uses PowerShell's `Invoke-ATHHTMLApplication` function to simulate mshta execution with JScript and user interaction. The key evidence includes:

**PowerShell Command Execution**: Security event 4688 shows PowerShell spawning with the command `"powershell.exe" & {Invoke-ATHHTMLApplication -HTAFilePath Test.hta -ScriptEngine JScript -SimulateUserDoubleClick}`, indicating the test framework's execution method.

**PowerShell Script Block Logging**: Multiple EID 4104 events capture the actual technique invocation: `& {Invoke-ATHHTMLApplication -HTAFilePath Test.hta -ScriptEngine JScript -SimulateUserDoubleClick}` and `{Invoke-ATHHTMLApplication -HTAFilePath Test.hta -ScriptEngine JScript -SimulateUserDoubleClick}`.

**Child Process Creation**: A whoami.exe process (PID 16568) is spawned as a child of PowerShell, suggesting the test successfully executed code within the HTA context.

**Process Access Events**: Sysmon EID 10 events show PowerShell accessing both the whoami.exe process and another PowerShell instance with 0x1FFFFF access rights, indicating comprehensive process control typical of code injection or execution frameworks.

**Normal PowerShell Telemetry**: Standard .NET assembly loading, pipe creation, and Windows Defender integration events consistent with PowerShell operation.

## What This Dataset Does Not Contain

Critically, this dataset lacks the most important telemetry for detecting actual mshta.exe abuse: **no mshta.exe process creation events are present**. The Atomic Red Team test appears to simulate the technique's effects through PowerShell rather than actually invoking mshta.exe, which significantly limits the dataset's detection engineering value.

Missing telemetry includes:
- Sysmon EID 1 events showing mshta.exe process creation with HTA file arguments
- Network connections (Sysmon EID 3) if the HTA were fetched remotely
- File creation events for the Test.hta file referenced in the command
- Image load events showing mshta.exe loading scripting engines
- DNS queries or HTTP requests associated with remote HTA retrieval

The sysmon-modular configuration's include-mode filtering for ProcessCreate events means mshta.exe might not be captured unless it matches specific suspicious patterns, but this appears to be a test framework limitation rather than a configuration issue.

## Assessment

This dataset has limited utility for developing detections against actual T1218.005 mshta abuse. While it demonstrates a testing framework's approach to simulating the technique, it lacks the fundamental telemetry that real mshta.exe execution would generate. Detection engineers would be better served by datasets containing actual mshta.exe process creation, command-line arguments, and associated network or file system activity.

The PowerShell telemetry is well-captured and could support detections of this specific testing tool, but wouldn't translate to detecting genuine mshta abuse. The dataset is more valuable for understanding Atomic Red Team's testing methodology than for building production detection rules.

## Detection Opportunities Present in This Data

1. **PowerShell-based Testing Framework Detection**: Monitor for PowerShell script blocks containing `Invoke-ATHHTMLApplication` function calls as indicators of red team testing activity.

2. **Suspicious PowerShell Command Patterns**: Alert on PowerShell executions with `-HTAFilePath` and `-ScriptEngine` parameters that suggest HTA simulation attempts.

3. **PowerShell Child Process Spawning**: Detect PowerShell processes spawning reconnaissance utilities like whoami.exe, especially when combined with HTA-related command-line arguments.

4. **Comprehensive Process Access Rights**: Monitor for processes obtaining 0x1FFFFF (PROCESS_ALL_ACCESS) rights against newly spawned child processes, indicating potential code injection or execution control.

5. **PowerShell Process-to-Process Access**: Flag instances where PowerShell accesses other PowerShell processes with high-level privileges, which may indicate lateral execution or privilege escalation attempts.

6. **Security Event 4688 Command-Line Analysis**: Create detections for process creation events containing both "powershell.exe" and HTA-related keywords in the command line, even when the actual mshta.exe process isn't present.
