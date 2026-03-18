# T1003.001-4: LSASS Memory — Dump LSASS.exe Memory using NanoDump

## Technique Context

T1003.001 (LSASS Memory) is a credential access technique where attackers dump memory from the Local Security Authority Subsystem Service (LSASS) process to extract plaintext credentials, NTLM hashes, and Kerberos tickets. LSASS is a critical Windows process that handles authentication and stores credentials in memory for single sign-on functionality.

NanoDump is a particularly interesting LSASS dumping tool because it's designed to be stealthy and minimize detection by traditional security solutions. It creates memory dumps using legitimate Windows APIs while attempting to evade common defensive measures. The detection community focuses heavily on process access events to LSASS, file creation of dump files, and the execution of known credential dumping tools.

## What This Dataset Contains

This dataset captures an incomplete execution of the NanoDump technique. The key evidence includes:

**Process execution chain**: Security event 4688 shows PowerShell spawning cmd.exe with command line `"cmd.exe" /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\nanodump.x64.exe -w "%temp%\nanodump.dmp"` (PID 3008), indicating the test attempted to execute NanoDump with output directed to a temporary dump file.

**Process access attempt**: Sysmon event 10 shows the PowerShell process (PID 6500) accessing cmd.exe (PID 3008) with GrantedAccess 0x1FFFFF, but notably missing is the critical LSASS process access that would indicate successful credential dumping.

**Process termination**: Security event 4689 shows cmd.exe exited with status 0x1 (failure), suggesting the NanoDump execution was unsuccessful.

**Supporting telemetry**: Standard PowerShell initialization events (test framework boilerplate with Set-ExecutionPolicy), process creation events for whoami.exe (system reconnaissance), and various DLL loading events for PowerShell components.

## What This Dataset Does Not Contain

Critically missing are the events that would indicate successful LSASS memory dumping:
- No Sysmon event 10 showing process access to lsass.exe (the primary detection indicator)
- No file creation events for the actual dump file "nanodump.dmp" in the temp directory
- No Sysmon event 1 for the nanodump.x64.exe process itself, indicating the sysmon-modular config filtered it or it failed to execute

The cmd.exe exit status of 0x1 strongly suggests Windows Defender or another security control blocked the NanoDump execution before it could access LSASS memory. The PowerShell script block logs contain only test framework boilerplate, providing no insight into the actual technique execution.

## Assessment

This dataset has limited utility for building detections of successful LSASS memory dumping since the technique was blocked before completion. However, it provides excellent telemetry for detecting attempted credential dumping activities. The command line evidence in Security 4688 events clearly shows the attack attempt with the nanodump.x64.exe path and -w flag for writing dump files.

For detection engineering, this represents a common scenario where endpoint protection blocks the technique but still generates valuable attempt indicators. The process execution chain and command line artifacts are sufficient for alerting on credential dumping tool usage, even when the tool fails to execute successfully.

## Detection Opportunities Present in This Data

1. **Command line detection** - Security 4688 events containing "nanodump" or paths to ExternalPayloads directory with credential dumping tool names
2. **Process chain analysis** - PowerShell spawning cmd.exe with credential dumping tool command lines (parent process powershell.exe, child process cmd.exe with dump tool parameters)
3. **Failed execution monitoring** - cmd.exe processes with exit code 0x1 following credential tool execution attempts
4. **Suspicious process access patterns** - Sysmon 10 events showing PowerShell accessing newly created processes with high privileges (0x1FFFFF)
5. **Tool staging detection** - File paths containing "AtomicRedTeam" or "ExternalPayloads" directories combined with known credential access tools
6. **Process privilege escalation** - Security 4703 events showing token privilege adjustments (SeDebugPrivilege, SeSecurityPrivilege) in PowerShell processes preceding credential access attempts
