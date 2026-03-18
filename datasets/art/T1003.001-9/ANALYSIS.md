# T1003.001-9: LSASS Memory — Create Mini Dump of LSASS.exe using ProcDump

## Technique Context

T1003.001 (LSASS Memory) is a credential access technique where attackers dump the memory of the Local Security Authority Subsystem Service (LSASS) process to extract plaintext passwords, password hashes, and Kerberos tickets. ProcDump is a legitimate Microsoft Sysinternals utility commonly used by attackers for this purpose because it can create memory dumps with minimal detection compared to other tools. The detection community focuses on monitoring for LSASS access patterns, process creation of dump utilities, file creation of dump files, and privilege escalation events that enable memory dumping.

## What This Dataset Contains

This dataset captures an attempt to use ProcDump to create a memory dump of LSASS that was blocked by Windows Defender. The key evidence includes:

**Process Creation Chain:**
- Security 4688 shows PowerShell (PID 0x1a38) spawning cmd.exe (PID 0x78) with command line: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\procdump.exe" -accepteula -mm lsass.exe C:\Windows\Temp\lsass_dump.dmp`
- The cmd.exe process exited with status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the operation

**Privilege Escalation:**
- Security 4703 shows PowerShell (PID 0x1a38) enabling multiple high-value privileges including `SeDebugPrivilege`, `SeBackupPrivilege`, and `SeRestorePrivilege` - privileges typically required for LSASS memory access

**Process Activity:**
- Sysmon EID 1 captures whoami.exe execution for system reconnaissance
- Sysmon EID 10 shows PowerShell accessing whoami.exe with full access rights (0x1FFFFF)
- Sysmon EID 8 captures CreateRemoteThread activity from PowerShell to an unknown process (PID 120)

**PowerShell Telemetry:**
- Security 4688 captures the full command line showing ProcDump invocation with LSASS targeting
- PowerShell events contain only test framework boilerplate (Set-ExecutionPolicy Bypass, Set-StrictMode)

## What This Dataset Does Not Contain

This dataset lacks several key artifacts because Windows Defender successfully blocked the technique:

**Missing ProcDump Process Creation:** No Sysmon EID 1 or Security 4688 events for procdump.exe execution, as Defender prevented the process from starting

**Missing LSASS Access Events:** No Sysmon EID 10 events showing direct LSASS process access, which would normally be the primary detection opportunity

**Missing Dump File Creation:** No Sysmon EID 11 events for lsass_dump.dmp file creation in C:\Windows\Temp\, as the dump operation never succeeded

**Missing Network Activity:** No Sysmon network events, as this was a local credential dumping attempt

The sysmon-modular configuration's include-mode filtering for ProcessCreate explains why we don't see procdump.exe in Sysmon EID 1 - the process was blocked before creation, so it wouldn't match the suspicious process patterns anyway.

## Assessment

This dataset provides excellent evidence of a blocked LSASS dumping attempt. The combination of Security 4688 command-line logging, Security 4703 privilege escalation events, and the distinctive exit code 0xC0000022 creates a strong detection pattern. While we don't see the actual LSASS access or dump file creation due to successful blocking, the preparatory activities and command-line evidence are sufficient for high-confidence detection. The privilege escalation events are particularly valuable as they occur before the blocking and indicate clear intent to perform memory dumping operations.

## Detection Opportunities Present in This Data

1. **Command Line Analysis:** Detect cmd.exe or PowerShell command lines containing "procdump.exe", "-mm", and "lsass" parameters in Security 4688 events

2. **Process Exit Code Monitoring:** Alert on processes exiting with status 0xC0000022 (ACCESS_DENIED) when the command line indicates credential dumping tools like ProcDump

3. **Privilege Escalation Correlation:** Detect Security 4703 events showing elevation of SeDebugPrivilege, SeBackupPrivilege, or SeRestorePrivilege followed by suspicious process creation

4. **PowerShell Credential Access Pattern:** Monitor PowerShell processes (Security 4688) spawning cmd.exe with external payload execution patterns targeting LSASS

5. **Tool Path Analysis:** Detect execution attempts of tools from non-standard paths like "AtomicRedTeam\atomics\..\ExternalPayloads\" combined with LSASS-related parameters

6. **CreateRemoteThread Anomalies:** Investigate Sysmon EID 8 CreateRemoteThread events from PowerShell to unknown processes, especially when correlated with failed credential access attempts

7. **Defender Block Correlation:** Combine failed process execution (exit code 0xC0000022) with privilege escalation events and credential dumping tool invocation for high-confidence alerting
