# T1003.001-6: LSASS Memory — Offline Credential Theft With Mimikatz

## Technique Context

T1003.001 (LSASS Memory) involves extracting credential material from the Local Security Authority Subsystem Service (LSASS) process memory. This is a foundational post-exploitation technique that attackers use to harvest plaintext passwords, NTLM hashes, Kerberos tickets, and other authentication artifacts from memory. The technique is particularly valuable because it can provide credentials for lateral movement and privilege escalation within Active Directory environments.

Mimikatz is the archetypal tool for this technique, capable of reading LSASS memory directly or processing memory dumps created by legitimate tools like ProcDump or Task Manager. The detection community focuses on monitoring process access to LSASS with suspicious access rights (particularly 0x1010 and 0x1FFFFF), memory dump creation in sensitive directories, and the execution of known credential harvesting tools.

## What This Dataset Contains

This dataset captures a blocked Mimikatz execution attempt where the technique was prevented by Windows Defender. The key evidence includes:

Security event 4688 shows cmd.exe spawning with the full Mimikatz command line: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\x64\mimikatz.exe" "sekurlsa::minidump %tmp%\lsass.DMP" "sekurlsa::logonpasswords full" exit`, followed by Security event 4689 showing the cmd.exe process exiting with status 0xC0000022 (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution.

Sysmon events document the process chain leading up to the blocked execution: multiple PowerShell processes (PIDs 3660, 6292, 6912) with extensive .NET runtime loading events (EID 7), privilege escalation captured in Security event 4703 showing the PowerShell process enabling high-privilege tokens including SeBackupPrivilege and SeRestorePrivilege, and Sysmon EID 1 capturing whoami.exe execution for system enumeration.

The PowerShell channel contains only test framework boilerplate - Set-StrictMode calls and Set-ExecutionPolicy Bypass commands without the actual technique implementation.

## What This Dataset Does Not Contain

The dataset lacks the core technique artifacts because Windows Defender successfully blocked Mimikatz execution. Missing elements include: no Mimikatz process creation events (blocked before execution), no LSASS process access events (Sysmon EID 10 with GrantedAccess targeting LSASS PID), no memory dump file creation in %TEMP% (the lsass.DMP file referenced in the command line), and no credential extraction output or related file operations.

The Sysmon ProcessCreate events are limited because the sysmon-modular configuration uses include-mode filtering - it only captures processes matching known-suspicious patterns, so standard processes in the execution chain may not appear in Sysmon EID 1.

## Assessment

This dataset provides excellent evidence of Windows Defender's effectiveness at blocking credential harvesting attempts but limited value for detection engineering focused on successful technique execution. The command-line capture in Security 4688 is valuable for signature-based detection, and the privilege escalation patterns in Security 4703 demonstrate the preparatory actions that often precede LSASS access attempts.

For detection engineering purposes, this dataset is most useful for understanding blocked execution patterns and building detections around attempt indicators rather than successful technique artifacts. The complete command-line visibility and process exit status provide clear indicators of defensive tool intervention.

## Detection Opportunities Present in This Data

1. **Command-line pattern matching** on Security 4688 events for "mimikatz.exe" execution with credential harvesting parameters like "sekurlsa::" commands
2. **Process exit status monitoring** for Security 4689 events showing exit code 0xC0000022 (STATUS_ACCESS_DENIED) combined with suspicious parent processes
3. **Privilege escalation detection** using Security 4703 events when PowerShell processes enable SeBackupPrivilege and SeRestorePrivilege simultaneously
4. **Suspicious process chains** correlating PowerShell spawning cmd.exe with credential harvesting tool paths in the command line
5. **Tool staging detection** monitoring for file paths containing "ExternalPayloads" or "AtomicRedTeam" directories combined with credential harvesting executables
6. **Failed execution correlation** linking blocked malicious processes with preceding system enumeration activities like whoami.exe execution from PowerShell
