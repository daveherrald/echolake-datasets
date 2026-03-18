# T1003.001-3: LSASS Memory — Dump LSASS.exe Memory using direct system calls and API unhooking

## Technique Context

T1003.001 (LSASS Memory) is a critical credential access technique where attackers extract plaintext credentials, password hashes, and Kerberos tickets from the Local Security Authority Subsystem Service (LSASS) process memory. This specific test implements an advanced evasion approach using direct system calls and API unhooking via the Outflank-Dumpert tool, designed to bypass EDR monitoring that relies on userland API hooking. The detection community focuses heavily on process access events targeting LSASS (PID 656 on most systems), suspicious privilege escalations (especially SeDebugPrivilege), and file creation of memory dump artifacts. This technique represents a sophisticated threat as it can bypass many traditional LSASS monitoring approaches.

## What This Dataset Contains

The dataset captures a failed LSASS dumping attempt that was blocked by Windows Defender. The key telemetry shows:

**Process Chain**: PowerShell (PID 6364) spawned `cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\Outflank-Dumpert.exe"` (PID 5464), but Outflank-Dumpert.exe itself never appears in process creation events, indicating Defender blocked its execution.

**Critical Privilege Escalation**: Security event 4703 shows PowerShell enabled multiple high-privilege tokens including `SeDebugPrivilege`, `SeBackupPrivilege`, and `SeRestorePrivilege` — privileges commonly required for LSASS memory access.

**Process Access Patterns**: Sysmon EID 10 events show PowerShell accessing child processes (whoami.exe PID 6544 and cmd.exe PID 5464) with full access rights (`GrantedAccess: 0x1FFFFF`), demonstrating the process manipulation capabilities available to the tool.

**Exit Status Indicators**: Security events show cmd.exe processes exiting with status `0x1` (error), confirming the tool execution failed rather than completing successfully.

**PowerShell Telemetry**: Limited to execution policy bypass commands (`Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`) with no malicious script content captured.

## What This Dataset Does Not Contain

**No LSASS Access Events**: Most critically, there are no Sysmon EID 10 events showing process access to lsass.exe (typically PID 656), which would be the primary indicator of successful LSASS dumping attempts. This absence confirms Defender's intervention.

**No Memory Dump Artifacts**: No Sysmon EID 11 file creation events for typical dump file extensions (.dmp, .dump, .out) that would indicate successful memory extraction.

**No Outflank-Dumpert Process Creation**: The actual tool execution was blocked, so no Sysmon EID 1 process creation event exists for the dumping tool itself — only the cmd.exe wrapper that attempted to launch it.

**Limited Network Activity**: No Sysmon EID 3 network connections that might indicate exfiltration of dumped credentials.

## Assessment

This dataset provides moderate detection engineering value, primarily as an example of *attempted* LSASS dumping that was successfully blocked by endpoint protection. The telemetry is most valuable for detecting the preparatory phases of LSASS attacks — privilege escalation patterns, process spawning behaviors, and command-line indicators. However, the lack of actual LSASS interaction limits its utility for developing detections of successful memory dumping. The privilege escalation telemetry in Security EID 4703 is particularly valuable, as these privilege combinations are strong indicators of credential dumping attempts regardless of the specific tool used.

## Detection Opportunities Present in This Data

1. **Privilege Escalation Monitoring**: Security EID 4703 showing simultaneous enablement of SeDebugPrivilege, SeBackupPrivilege, and SeRestorePrivilege within PowerShell processes

2. **Suspicious Command Line Patterns**: Security EID 4688 command line `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\Outflank-Dumpert.exe"` containing explicit references to credential dumping tools

3. **Process Access with Full Rights**: Sysmon EID 10 events showing PowerShell accessing child processes with maximum granted access (`0x1FFFFF`), indicating process manipulation capabilities

4. **PowerShell Execution Policy Bypass**: PowerShell EID 4103 showing `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` which often precedes malicious script execution

5. **Failed Process Execution Patterns**: Security EID 4689 exit status `0x1` combined with missing expected child process creation events, indicating blocked malicious tool execution

6. **Atomic Red Team Artifact Detection**: File paths containing `\AtomicRedTeam\` or `\ExternalPayloads\` in command lines indicating testing or attack simulation activity
