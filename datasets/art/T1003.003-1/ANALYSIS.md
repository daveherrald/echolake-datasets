# T1003.003-1: NTDS — Create Volume Shadow Copy with vssadmin

## Technique Context

T1003.003 (NTDS) involves attackers extracting credential material from the Windows NT Directory Services (NTDS.dit) database, which contains password hashes for all domain users. This technique is a cornerstone of post-exploitation credential harvesting in Active Directory environments. Attackers commonly create Volume Shadow Copy Service (VSS) snapshots to access the locked NTDS.dit file, then extract and crack the hashes offline. The detection community focuses on monitoring VSS operations (particularly `vssadmin.exe` and `wmic.exe` shadow copy creation), file access to NTDS.dit or its shadow copies, and the presence of credential dumping tools like `ntdsutil.exe` or `esentutl.exe`.

## What This Dataset Contains

This dataset captures a failed attempt to create a volume shadow copy using `vssadmin.exe`. The key evidence includes:

**Process Creation Chain (Security 4688 & Sysmon 1):**
- PowerShell spawned cmd.exe: `"cmd.exe" /c vssadmin.exe create shadow /for=C:`
- cmd.exe spawned vssadmin.exe: `vssadmin.exe create shadow /for=C:`

**Critical Exit Status (Security 4689):**
- vssadmin.exe exited with status `0x2` (error condition)
- cmd.exe also exited with status `0x2` (propagated error)

**Privilege Activity (Security 4703):**
- vssadmin.exe enabled `SeBackupPrivilege` before attempting the shadow copy operation
- PowerShell process shows extensive privilege elevation including `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeManageVolumePrivilege`

**Sysmon Activity:**
- ProcessCreate events for whoami.exe (T1033), cmd.exe (T1059.003), and vssadmin.exe (T1490)
- ProcessAccess events showing PowerShell accessing both whoami.exe and cmd.exe processes
- Multiple PowerShell-related DLL loads and named pipe creation

## What This Dataset Does Not Contain

The dataset shows a **failed execution** — vssadmin.exe exited with error code 0x2, indicating the shadow copy creation was unsuccessful. This means there are no:
- Successful shadow copy creation events
- File access to NTDS.dit or shadow volumes
- Registry entries for new shadow copies
- Volume shadow service provider activities
- Subsequent credential extraction attempts

The PowerShell channel contains only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) without the actual test execution PowerShell commands. No Sysmon ProcessCreate events exist for the initial PowerShell processes due to the sysmon-modular include-mode filtering that only captures known-suspicious patterns.

## Assessment

This dataset provides moderate value for detection engineering, particularly for **attempt-based detection**. The combination of Security 4688/4689 events with command-line logging and Sysmon 1 events clearly shows the attack pattern despite the failed execution. The privilege escalation telemetry (Security 4703) is especially valuable as `SeBackupPrivilege` enablement is a strong indicator of credential access attempts. However, the failed execution limits the dataset's utility for testing detections that rely on successful VSS operations or subsequent file access patterns. The error condition actually makes this dataset useful for testing detection logic that should trigger on **attempts** rather than just successful executions.

## Detection Opportunities Present in This Data

1. **vssadmin.exe Process Creation with Shadow Copy Arguments** - Security 4688 and Sysmon 1 events showing `vssadmin.exe create shadow /for=C:` command line

2. **SeBackupPrivilege Enablement by vssadmin.exe** - Security 4703 event showing privilege escalation specifically for backup operations

3. **PowerShell Spawning System Administration Tools** - Process chain from powershell.exe → cmd.exe → vssadmin.exe with suspicious arguments

4. **Command Shell Execution with VSS Commands** - Sysmon 1 rule match on T1059.003 for cmd.exe executing volume shadow operations

5. **Multiple High-Impact Privileges Enabled by PowerShell** - Security 4703 showing PowerShell with SeBackupPrivilege, SeRestorePrivilege, SeManageVolumePrivilege, and others

6. **Cross-Process Access from PowerShell to System Tools** - Sysmon 10 events showing PowerShell accessing both whoami.exe and cmd.exe processes with full access rights

7. **System Discovery Preceding Credential Access** - Sysmon 1 detection of whoami.exe (T1033) immediately before vssadmin execution, indicating reconnaissance

8. **Inhibit System Recovery Tool Usage** - Sysmon 1 rule match on T1490 for vssadmin.exe usage in credential access context
