# T1003.001-14: LSASS Memory — Dump LSASS.exe Memory through Silent Process Exit

## Technique Context

T1003.001 (LSASS Memory) is a credential access technique where adversaries dump memory from the Local Security Authority Subsystem Service (LSASS) process to extract plaintext credentials, NTLM hashes, and Kerberos tickets. The "Silent Process Exit" method is a sophisticated approach that configures Windows Error Reporting to automatically dump a target process when it exits, avoiding direct memory access to the running LSASS process.

This technique leverages the Windows Silent Process Exit mechanism, typically configured via registry keys under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\`, to trigger automatic memory dumps. The detection community focuses on registry modifications to these keys, unusual process access patterns to LSASS, and the presence of memory dump files in unexpected locations.

## What This Dataset Contains

The data shows a PowerShell-initiated execution attempting to use nanodump with the `--silent-process-exit` parameter. Key evidence includes:

**Process Chain**: PowerShell (PID 1888) → cmd.exe (PID 5752) with command line `"cmd.exe" /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\nanodump.x64.exe --silent-process-exit "%temp%\SilentProcessExit"`

**Process Access**: Sysmon EID 10 events show PowerShell accessing both whoami.exe (PID 1668) and cmd.exe (PID 5752) with full access rights (0x1FFFFF), indicating process monitoring behavior

**Execution Evidence**: Security EID 4688 shows the cmd.exe process creation with the nanodump command line, and EID 4689 shows it exited with status code 0x1 (failure)

**Privilege Activity**: Security EID 4703 documents extensive privilege enablement including SeDebugPrivilege, SeBackupPrivilege, and other high-impact rights typically needed for memory dumping

The PowerShell channel contains only standard test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no technique-specific script content.

## What This Dataset Does Not Contain

Critically missing from this dataset are the core indicators of successful Silent Process Exit configuration:

- **No Registry Events**: Missing Sysmon EID 12/13 events for registry key creation/modification under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\`
- **No LSASS Access**: No Sysmon EID 10 events showing process access to lsass.exe
- **No Dump Files**: No Sysmon EID 11 events indicating creation of memory dump files
- **No nanodump Process**: The nanodump.x64.exe process itself doesn't appear in Sysmon ProcessCreate events, likely filtered by the include-mode configuration

The cmd.exe exit status of 0x1 suggests the nanodump execution failed, possibly due to Windows Defender intervention or insufficient privileges, preventing the technique from completing successfully.

## Assessment

This dataset provides limited value for detection engineering focused on successful Silent Process Exit LSASS dumping. While it captures the initial execution attempt with clear command-line evidence, it lacks the registry modifications and file system artifacts that are the primary detection opportunities for this technique variant.

The process access events and privilege escalation telemetry are valuable for behavioral detection, but the absence of registry events significantly diminishes the dataset's utility for building comprehensive detections. The failure mode captured here is more useful for understanding defensive efficacy than attack methodology.

## Detection Opportunities Present in This Data

1. **Command Line Analysis**: Security EID 4688 showing nanodump execution with `--silent-process-exit` parameter - rare and highly suspicious binary/argument combination

2. **Process Access Anomalies**: Sysmon EID 10 showing PowerShell accessing recently spawned processes with full access rights (0x1FFFFF) - unusual parent-child access pattern

3. **Privilege Abuse**: Security EID 4703 showing simultaneous enablement of multiple high-impact privileges including SeDebugPrivilege and SeBackupPrivilege by PowerShell

4. **Tool Presence**: File path references to `C:\AtomicRedTeam\atomics\..\ExternalPayloads\nanodump.x64.exe` indicating presence of known credential dumping tools

5. **Process Chain Context**: PowerShell spawning cmd.exe with credential access tool parameters - suspicious process relationship for legitimate administrative activity
