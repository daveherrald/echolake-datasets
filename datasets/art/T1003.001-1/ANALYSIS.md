# T1003.001-1: LSASS Memory — Dump LSASS.exe Memory using ProcDump

## Technique Context

T1003.001 (LSASS Memory) is a critical credential access technique where attackers dump the memory of the Local Security Authority Subsystem Service (lsass.exe) to extract plaintext passwords, NTLM hashes, Kerberos tickets, and other authentication material. This technique is fundamental to lateral movement and privilege escalation in Windows environments. Attackers commonly use tools like Mimikatz, ProcDump, Task Manager, or custom malware to perform LSASS dumps. Detection engineers focus on monitoring process access to lsass.exe with suspicious permissions, file creation of dump files, and the use of known dumping utilities. The technique is particularly concerning because LSASS memory often contains credentials for recently logged-in users, making it a high-value target for attackers.

## What This Dataset Contains

This dataset captures a ProcDump-based LSASS memory dump attempt that was blocked by Windows Defender. The key evidence shows:

**Process Creation Chain**: Security event 4688 shows PowerShell (PID 1284) spawning cmd.exe (PID 6264) with the command line `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\procdump.exe" -accepteula -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp`. The cmd.exe process exits with status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the operation.

**Sysmon Process Access**: Event 10 shows PowerShell (PID 1284) accessing whoami.exe (PID 6220) with granted access `0x1FFFFF` (PROCESS_ALL_ACCESS), demonstrating the high privilege level of the parent process.

**CreateRemoteThread Activity**: Event 8 captures PowerShell injecting a thread into an unknown process (PID 6264), which aligns with the cmd.exe process from the blocked command execution.

**Privilege Escalation**: Security event 4703 shows the PowerShell process enabling multiple high-privilege tokens including SeBackupPrivilege, SeRestorePrivilege, and SeSecurityPrivilege - privileges commonly required for LSASS access.

## What This Dataset Does Not Contain

This dataset lacks the actual LSASS memory dumping activity because Windows Defender successfully blocked the ProcDump execution before it could access lsass.exe. Notably missing are:

- Sysmon event 10 (ProcessAccess) showing direct access to lsass.exe
- File creation events for the intended dump file `C:\Windows\Temp\lsass_dump.dmp`
- ProcessCreate events for procdump.exe itself (the sysmon-modular config may not include ProcDump in its suspicious process patterns)
- Any actual credential extraction or suspicious network activity that would follow successful LSASS dumping

The PowerShell script block logging contains only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) rather than the actual attack commands, as the execution was blocked early in the process chain.

## Assessment

This dataset provides excellent telemetry for detecting attempted LSASS memory dumps using ProcDump, even when the attack is blocked. The combination of Security 4688 events with full command-line logging and Sysmon process access events creates a comprehensive picture of the attack attempt. The privilege adjustment event (4703) is particularly valuable as it shows the elevated permissions being acquired before the attempted dump. However, the dataset's utility is somewhat limited for understanding successful LSASS dumps since the attack was prevented. Detection engineers should note that this pattern - where process creation succeeds but the target operation fails with STATUS_ACCESS_DENIED - is common in environments with active endpoint protection.

## Detection Opportunities Present in This Data

1. **Command Line Detection**: Monitor Security 4688 events for command lines containing "procdump.exe" with "-ma lsass.exe" parameters, especially when executed via cmd.exe spawned from PowerShell

2. **Process Exit Code Monitoring**: Alert on cmd.exe processes exiting with status 0xC0000022 (STATUS_ACCESS_DENIED) when the command line contains LSASS dumping tools

3. **Privilege Adjustment Correlation**: Detect Security 4703 events showing SeBackupPrivilege, SeRestorePrivilege, or SeSecurityPrivilege being enabled, especially when correlated with subsequent process creation of dumping tools

4. **Parent-Child Process Relationships**: Monitor for PowerShell spawning cmd.exe with external executable paths (particularly from temp directories or non-standard locations)

5. **CreateRemoteThread to Unknown Processes**: Alert on Sysmon event 8 where PowerShell injects threads into unidentified target processes, which may indicate process manipulation attempts

6. **High-Privilege Process Access**: Monitor Sysmon event 10 for processes accessing other processes with PROCESS_ALL_ACCESS (0x1FFFFF) permissions, particularly from scripting engines like PowerShell
