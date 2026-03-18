# T1003.003-2: NTDS — Copy NTDS.dit from Volume Shadow Copy

## Technique Context

T1003.003 (NTDS) involves adversaries attempting to access or create a copy of the Active Directory domain database (ntds.dit) to extract credentials. The ntds.dit file contains password hashes for all domain users, making it a high-value target for credential harvesting. Attackers commonly use Volume Shadow Copy (VSS) to access locked files like ntds.dit, since the database is typically in use and locked during normal domain controller operations.

This technique is frequently observed in post-exploitation activities where attackers have already gained administrative access to a domain controller. The detection community focuses on monitoring for VSS operations, file access patterns targeting ntds.dit, and the use of built-in Windows utilities like `vssadmin`, `wmic`, or direct access via the `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy` path structure.

## What This Dataset Contains

This dataset captures a failed attempt to copy ntds.dit from a Volume Shadow Copy using the classic GLOBALROOT device path technique. The key evidence includes:

**Security Event 4688** shows the malicious command execution: `"cmd.exe" /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Windows\Temp\ntds.dit & copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Windows\Temp\VSC_SYSTEM_HIVE & reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM_HIVE`

**Security Event 4689** reveals the cmd.exe process exited with status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender or security controls blocked the operation.

**Security Event 4703** shows privilege escalation with multiple sensitive privileges enabled including `SeBackupPrivilege` and `SeRestorePrivilege`, which are commonly required for VSS operations.

**Sysmon Events** capture the process creation of `whoami.exe` (Event ID 1) and various PowerShell.NET assembly loads, but notably absent are any Sysmon ProcessCreate events for the actual `cmd.exe` execution due to the include-mode filtering configuration.

## What This Dataset Does Not Contain

The dataset lacks several critical elements due to Windows Defender intervention:

- No successful file creation events showing ntds.dit or SYSTEM hive copies in the target directories
- No VSS creation commands (vssadmin, wmic) in the process chain, suggesting the shadow copy already existed
- Missing Sysmon ProcessCreate events for cmd.exe due to sysmon-modular's include-mode filtering that only captures known suspicious binaries
- No network activity or subsequent credential extraction tools, as the initial file copy was blocked
- No registry save operation telemetry, as the command chain failed at the first copy operation

The PowerShell script block logging contains only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) rather than the actual attack commands.

## Assessment

This dataset provides excellent telemetry for detecting attempted Volume Shadow Copy-based ntds.dit theft, particularly the blocked variant. The Security event logs with full command-line auditing capture the complete attack string, making detection straightforward. The combination of Security 4688 process creation with the distinctive GLOBALROOT path pattern and Security 4689 with STATUS_ACCESS_DENIED provides clear indicators of both the technique and its failure.

The privilege escalation event (Security 4703) showing SeBackupPrivilege activation adds valuable context for privilege-based detection rules. However, the lack of Sysmon ProcessCreate for cmd.exe highlights the importance of Security event logs for comprehensive process monitoring in environments using filtered Sysmon configurations.

## Detection Opportunities Present in This Data

1. **GLOBALROOT Device Path Detection** - Monitor Security 4688 command lines for `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy` patterns attempting to access ntds.dit or SYSTEM files

2. **Multi-Command NTDS Theft Pattern** - Detect command chains combining ntds.dit copy, SYSTEM hive extraction, and registry save operations in a single cmd.exe execution

3. **Failed File Access with STATUS_ACCESS_DENIED** - Alert on Security 4689 events with exit code 0xC0000022 when the parent command involved credential database file paths

4. **Backup Privilege Escalation** - Monitor Security 4703 events showing SeBackupPrivilege and SeRestorePrivilege activation, especially when combined with file system access attempts

5. **PowerShell-to-CMD Credential Harvesting Chain** - Detect PowerShell processes spawning cmd.exe with file copy operations targeting Windows\NTDS or System32\config paths

6. **Volume Shadow Copy Enumeration Context** - Look for GLOBALROOT access attempts referencing specific shadow copy numbers (HarddiskVolumeShadowCopy1, etc.) indicating prior VSS reconnaissance
