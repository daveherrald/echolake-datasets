# T1055.002-1: Portable Executable Injection — Portable Executable Injection

## Technique Context

T1055.002 (Portable Executable Injection) is a defense evasion and privilege escalation technique where adversaries inject a portable executable (PE) file into the memory of a running process. This differs from other process injection techniques by injecting an entire PE rather than shellcode or DLLs. Attackers use this technique to hide malicious code within legitimate processes, evade process-based defenses, and inherit the privileges of the target process. The detection community focuses on monitoring for suspicious process access patterns, memory allocation behaviors, and abnormal child process relationships that indicate PE injection attempts.

## What This Dataset Contains

This dataset captures a Windows Defender intervention blocking a PE injection attempt. The test begins with PowerShell executing the command `Start-Process "C:\AtomicRedTeam\atomics\T1055.002\bin\RedInjection.exe"`, visible in Security 4688 and PowerShell 4104 events. However, Windows Defender immediately blocks execution with PowerShell 4100 showing "This command cannot be run due to the error: Operation did not complete successfully because the file contains a virus or potentially unwanted software."

The dataset shows extensive Sysmon telemetry around PowerShell initialization and .NET runtime loading across multiple PowerShell processes (PIDs 19804, 19256, 20208, 20648). Process access events appear in Sysmon 10 with `GrantedAccess: 0x1FFFFF` showing PowerShell accessing both whoami.exe and another PowerShell process, tagged by sysmon-modular as "technique_id=T1055.001,technique_name=Dynamic-link Library Injection".

Windows Defender's scanning activity is evident in Sysmon 2 (file creation time changed for RedInjection.exe) and Sysmon 11 (temporary file creation by MsMpEng.exe). The test execution includes a whoami.exe process creation captured in both Sysmon 1 and Security 4688 events.

## What This Dataset Does Not Contain

The dataset does not contain evidence of successful PE injection because Windows Defender blocked the RedInjection.exe binary before it could execute and perform the injection. There are no process hollowing indicators, no suspicious memory allocations, and no evidence of malicious code running within target processes. The Sysmon ProcessCreate events for RedInjection.exe itself are absent, confirming that Defender prevented the binary from launching.

Missing are the characteristic artifacts of successful PE injection: thread creation in remote processes, memory region modifications, and the spawning of Notepad.exe that the test was designed to inject into. The dataset also lacks network connections or file operations that would typically follow successful PE injection.

## Assessment

This dataset has limited utility for building detections of successful PE injection but high value for understanding endpoint protection interactions and attempted technique execution. The telemetry clearly demonstrates how modern EDR solutions can prevent technique completion while still generating valuable behavioral indicators. The process access events and PowerShell command-line logging provide good detection opportunities for attempted PE injection, even when the technique fails.

For comprehensive PE injection detection development, analysts would need datasets showing successful execution alongside this blocked attempt to understand the full technique spectrum.

## Detection Opportunities Present in This Data

1. **PE Injection Tool Command Line Detection** - Security 4688 and PowerShell 4104 events contain the explicit command `Start-Process "C:\AtomicRedTeam\atomics\T1055.002\bin\RedInjection.exe"` which indicates PE injection tool usage

2. **Suspicious Process Access Patterns** - Sysmon 10 events show PowerShell accessing other processes with full access rights (0x1FFFFF), particularly between parent/child PowerShell processes which may indicate injection preparation

3. **Windows Defender Malware Block Correlation** - PowerShell 4100 error "Operation did not complete successfully because the file contains a virus or potentially unwanted software" combined with file scanning activity (Sysmon 2) indicates blocked malicious PE execution

4. **Process Injection Tool Path Detection** - File paths containing "RedInjection.exe" or similar injection tool names in command lines, process creation events, or file access logs

5. **Abnormal PowerShell Child Process Relationships** - Multiple nested PowerShell processes with process access events between them, particularly when combined with execution policy bypass commands
