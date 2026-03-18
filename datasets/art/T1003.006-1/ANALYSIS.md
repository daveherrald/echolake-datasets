# T1003.006-1: DCSync — DCSync via mimikatz

## Technique Context

DCSync is a sophisticated credential access technique that exploits legitimate Windows domain replication protocols to extract password hashes and other sensitive data from domain controllers. Attackers use tools like mimikatz to impersonate domain controllers and request replication data, effectively "syncing" credentials without directly accessing LSASS or the domain controller's filesystem. This technique requires elevated privileges (typically domain admin or equivalent) and specific rights like "Replicating Directory Changes" and "Replicating Directory Changes All."

The detection community focuses heavily on identifying unusual replication requests, particularly from non-domain controller systems, monitoring for specific Kerberos ticket requests (TGS-REQ with specific service names), and watching for tools like mimikatz that implement DCSync functionality. This technique is particularly dangerous because it operates within normal Windows protocols, making it harder to distinguish from legitimate replication traffic.

## What This Dataset Contains

This dataset captures a DCSync attempt that was blocked by Windows Defender. The key evidence shows:

**Process execution chain**: Security event 4688 shows cmd.exe (PID 0x1080) being spawned by PowerShell with the command line `"cmd.exe" /c %tmp%\mimikatz\x64\mimikatz.exe "lsadump::dcsync /domain:%userdnsdomain% /user:krbtgt@%userdnsdomain%" "exit"`. This command line clearly shows the DCSync attempt targeting the krbtgt account.

**Access denial**: The cmd.exe process exits with status 0xC0000022 (STATUS_ACCESS_DENIED) according to Security event 4689, indicating Windows Defender blocked the execution before mimikatz could perform the actual DCSync operation.

**Process monitoring**: Sysmon captures extensive telemetry including ProcessCreate (EID 1) for whoami.exe execution, ProcessAccess (EID 10) showing PowerShell accessing the whoami process with full rights (0x1FFFFF), and CreateRemoteThread (EID 8) indicating process injection attempts.

**PowerShell activity**: The PowerShell events contain only standard test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no DCSync-specific script content captured.

**Privilege escalation**: Security event 4703 shows PowerShell enabling multiple high-privilege tokens including SeSecurityPrivilege, SeBackupPrivilege, and SeRestorePrivilege—privileges often required for DCSync operations.

## What This Dataset Does Not Contain

The dataset lacks the actual DCSync network traffic and Kerberos authentication events that would normally characterize this technique. Since Windows Defender blocked mimikatz execution, we don't see:

- Directory service access events that would show replication requests
- Kerberos authentication logs (4768, 4769) that would reveal TGS requests for directory services
- Network connections to domain controllers on port 135 or 445
- LDAP query logs showing requests for sensitive attributes
- The actual credential extraction or hash dumping artifacts

The Sysmon configuration's include-mode filtering means we're missing ProcessCreate events for the blocked mimikatz.exe execution, though the Security channel's 4688 event captures the command line attempt.

## Assessment

This dataset provides excellent evidence for detecting DCSync attempts at the process execution level, even when the technique is blocked by endpoint protection. The combination of Security event 4688 with the explicit mimikatz DCSync command line and the subsequent ACCESS_DENIED exit code creates a clear detection signature. However, the dataset's utility is limited for understanding successful DCSync operations or building detections based on network-level indicators, authentication patterns, or directory service access logs. The privilege token adjustments in event 4703 provide valuable context about the elevated rights being used.

## Detection Opportunities Present in This Data

1. **Command line pattern matching** - Security 4688 events containing "lsadump::dcsync" or mimikatz DCSync syntax patterns, especially targeting sensitive accounts like krbtgt
2. **Process execution with access denied** - CMD or PowerShell processes spawning credential access tools that immediately exit with STATUS_ACCESS_DENIED (0xC0000022)
3. **Privilege token escalation** - Security 4703 events showing processes enabling multiple high-privilege tokens (SeSecurityPrivilege, SeBackupPrivilege, SeRestorePrivilege) simultaneously
4. **Process injection patterns** - Sysmon EID 8 CreateRemoteThread events from PowerShell targeting unknown or short-lived processes
5. **Tool path indicators** - Command lines referencing typical mimikatz installation paths like "%tmp%\mimikatz\x64\mimikatz.exe"
6. **Process access with full rights** - Sysmon EID 10 showing PowerShell accessing other processes with GrantedAccess 0x1FFFFF
7. **Endpoint protection blocking patterns** - Correlation of tool execution attempts with immediate ACCESS_DENIED exit codes indicating security software intervention
