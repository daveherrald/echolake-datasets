# T1027.007-1: Dynamic API Resolution — Dynamic API Resolution-Ninja-syscall

## Technique Context

T1027.007 (Dynamic API Resolution) is a defense evasion technique where malware resolves Windows API functions at runtime rather than importing them statically. This technique helps evade static analysis and signature-based detection by hiding API calls from import tables. Attackers commonly use dynamic API resolution to:

- Evade static analysis tools that rely on import table enumeration
- Bypass API hooking solutions that target statically linked functions
- Obscure malicious functionality from automated sandbox analysis
- Implement direct system calls (syscalls) to bypass user-mode hooks

Detection engineers typically focus on identifying programs that enumerate process memory, resolve kernel32.dll exports, use GetProcAddress patterns, or make direct system calls. The community emphasizes monitoring for unusual process behavior, memory access patterns, and syscall invocation outside normal API flows.

## What This Dataset Contains

This dataset captures a successful execution of the "ninja_syscall1.exe" binary, which demonstrates dynamic API resolution through direct system calls. Key evidence includes:

**Process Execution Chain:** Security event 4688 shows PowerShell spawning the test binary: `"C:\AtomicRedTeam\atomics\T1027.007\bin\ninja_syscall1.exe"` (PID 4000). The parent PowerShell process executed with command line containing the full atomic test script.

**File System Activity:** Sysmon EID 11 events show the ninja_syscall1.exe process (PID 4000) successfully creating `C:\Users\Default\AppData\Local\Temp\hello.log` at 17:28:02.343, demonstrating that the binary's dynamic API resolution worked correctly to make file system calls.

**Process Access Patterns:** Sysmon EID 10 events capture PowerShell accessing both the whoami.exe process (PID 6808) and another PowerShell instance (PID 6876) with full access rights (0x1FFFFF), suggesting the parent process was monitoring or managing child processes.

**No Direct Syscall Telemetry:** Notably absent are specific events that would indicate direct system call usage - the binary executed successfully but its internal API resolution mechanisms are not directly visible in standard Windows event logs.

## What This Dataset Does Not Contain

**Sysmon ProcessCreate for ninja_syscall1.exe:** The target binary execution is not captured in Sysmon EID 1 events due to the sysmon-modular configuration using include-mode filtering. The binary path doesn't match known suspicious patterns, so only Security 4688 events captured this process creation.

**Memory Access Details:** While the technique involves resolving APIs dynamically, there are no Sysmon EID 8 (CreateRemoteThread) or detailed memory access patterns that would show the binary walking export tables or performing GetProcAddress-style operations.

**Network or Registry Activity:** The test binary appears to only perform local file operations, so there are no network connections or registry modifications that might typically accompany more complex dynamic API resolution scenarios.

**Windows Defender Alerts:** Despite active real-time protection, the ninja_syscall1.exe binary executed successfully without triggering endpoint protection, suggesting the technique effectively evaded signature-based detection.

## Assessment

This dataset provides limited visibility into the actual dynamic API resolution technique itself, but excellent evidence of successful evasion. The security value lies primarily in process execution telemetry and file system artifacts rather than detailed behavioral analysis of the API resolution mechanisms.

The Security 4688 events with full command-line logging provide the most actionable detection data, capturing both the test framework and target binary execution. The Sysmon file creation events confirm successful technique execution, but the lack of ProcessCreate events for the target binary highlights configuration gaps that could impact detection coverage.

For building robust detections of T1027.007, this dataset demonstrates the importance of comprehensive process monitoring beyond Sysmon's filtered approach, as the actual evasive binary execution was only captured through Windows Security auditing.

## Detection Opportunities Present in This Data

1. **Suspicious Binary Execution from Atomic Red Team Paths** - Security EID 4688 events showing process creation from `C:\AtomicRedTeam\atomics\T1027.007\bin\` directory structure indicating test tool usage

2. **PowerShell Spawning Unknown Executables** - Process creation events where PowerShell parent processes launch binaries outside standard Windows directories, particularly with Start-Process cmdlets

3. **File Creation in Temp Directories by Non-Standard Processes** - Sysmon EID 11 events showing ninja_syscall1.exe creating files in `C:\Users\Default\AppData\Local\Temp\`, unusual for non-system processes

4. **Process Access with Full Rights** - Sysmon EID 10 events showing PowerShell accessing other processes with 0x1FFFFF access rights, potentially indicating process injection preparation or monitoring

5. **Command Line Pattern Analysis** - Security events containing PowerShell scripts with Start-Process, Start-Sleep, and conditional file removal patterns that match automated testing frameworks

6. **Unsigned Binary Execution** - Cross-reference file creation events with process execution to identify when newly created or unsigned binaries are executed from temporary locations

7. **Parent-Child Process Relationship Anomalies** - PowerShell processes spawning multiple child processes in rapid succession, particularly when combined with file system activity in temp directories
