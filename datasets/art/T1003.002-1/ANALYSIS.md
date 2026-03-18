# T1003.002-1: Security Account Manager — Registry dump of SAM, creds, and secrets

## Technique Context

T1003.002 Security Account Manager is a credential access technique where attackers dump the Security Account Manager (SAM) database from the Windows registry to extract local account password hashes. The SAM database stores local user account information including hashed passwords, and is a primary target for credential harvesting on Windows systems. Attackers commonly use tools like `reg.exe`, PowerShell, or specialized utilities to export the SAM, SYSTEM, and SECURITY registry hives, which together contain the cryptographic keys and password hashes needed for offline cracking or pass-the-hash attacks. The detection community focuses on monitoring registry access patterns, file creation events for registry hive dumps, and the specific command-line patterns used to extract these sensitive databases.

## What This Dataset Contains

This dataset captures a failed attempt to dump registry hives using the built-in `reg.exe` utility. The attack chain begins with PowerShell execution and proceeds through the following process tree:

- PowerShell process (PID 4936) spawns `cmd.exe` (PID 6852) with command line: `"cmd.exe" /c reg save HKLM\sam %temp%\sam & reg save HKLM\system %temp%\system & reg save HKLM\security %temp%\security`
- The cmd process attempts to create three `reg.exe` child processes to dump each registry hive:
  - `reg save HKLM\sam C:\Windows\TEMP\sam` (PID 6172)
  - `reg save HKLM\system C:\Windows\TEMP\system` (PID 6868) 
  - `reg save HKLM\security C:\Windows\TEMP\security` (PID 6708)

All three `reg.exe` processes exit with status code `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender or system protections blocked the registry dump attempts. The Security event log in EID 4703 shows privilege escalation with `SeBackupPrivilege` and other sensitive privileges being enabled on the PowerShell process, demonstrating the elevated rights needed for this technique. Sysmon captures extensive process creation (EID 1), process access (EID 10), and CreateRemoteThread events (EID 8) showing the attack progression.

## What This Dataset Does Not Contain

The dataset lacks successful registry hive dumps due to Windows Defender blocking the operations. There are no file creation events for the actual SAM, SYSTEM, or SECURITY hive files in the temp directory, and no subsequent file access or exfiltration activities that would follow successful credential harvesting. The Sysmon EID 11 events only show PowerShell profile files being created, not the target registry dumps. Additionally, the dataset doesn't contain any follow-up credential cracking attempts, hash extraction activities, or lateral movement that would typically occur after successful SAM database extraction.

## Assessment

This dataset provides excellent telemetry for detecting attempted SAM database dumping, even when the technique is blocked by endpoint protection. The Security channel's EID 4688 events capture the complete command-line arguments including the suspicious `reg save HKLM\sam` patterns, while EID 4689 events with exit code `0xC0000022` clearly indicate blocked attempts. Sysmon's process creation events complement this with additional process lineage details and hash information. The privilege escalation evidence in EID 4703 adds valuable context about the elevated rights being used. While the technique ultimately failed, the telemetry demonstrates how modern endpoint protection creates detection opportunities even for blocked attacks, making this dataset highly valuable for building detections that catch both successful and unsuccessful credential access attempts.

## Detection Opportunities Present in This Data

1. **Registry Hive Dump Command Lines**: Monitor Security EID 4688 for command lines containing `reg save HKLM\sam`, `reg save HKLM\system`, or `reg save HKLM\security` patterns, which directly indicate SAM dumping attempts.

2. **Failed Registry Access with STATUS_ACCESS_DENIED**: Alert on Security EID 4689 process termination events where `reg.exe` exits with status code `0xC0000022`, indicating blocked registry hive access attempts.

3. **Suspicious Privilege Escalation**: Detect Security EID 4703 events where PowerShell processes enable sensitive privileges like `SeBackupPrivilege`, `SeRestorePrivilege`, or `SeSecurityPrivilege` in combination with subsequent reg.exe spawning.

4. **Process Tree Analysis**: Monitor for PowerShell spawning cmd.exe which then creates multiple reg.exe child processes with registry hive arguments, indicating systematic credential harvesting attempts.

5. **Batch Command Registry Operations**: Look for cmd.exe processes with command lines containing multiple `reg save` operations chained with `&` operators, which is a common pattern for dumping multiple registry hives simultaneously.

6. **Sysmon Process Creation Correlation**: Correlate Sysmon EID 1 events showing reg.exe creation with command lines targeting HKLM\SAM, SYSTEM, or SECURITY hives, providing additional process lineage and hash-based detection capabilities.
