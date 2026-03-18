# T1003.003-3: NTDS — Dump Active Directory Database with NTDSUtil

## Technique Context

T1003.003 (NTDS) involves extracting credential data from the Active Directory database (NTDS.dit), a critical technique for credential access in domain environments. Attackers use this method to obtain password hashes for all domain users, enabling lateral movement and privilege escalation through techniques like pass-the-hash or password cracking. The NTDS.dit file contains NTLM hashes, Kerberos keys, and other sensitive authentication data that represents the crown jewels of domain credential theft.

NTDSUtil is Microsoft's legitimate database maintenance utility for Active Directory Domain Services. When used with the "ifm" (Install From Media) command, it creates a backup copy of the NTDS.dit database along with the SYSTEM registry hive needed to decrypt the password hashes. This technique is particularly dangerous because it uses a built-in Windows tool, making it harder to detect than third-party credential dumping tools. Detection engineers typically focus on monitoring NTDSUtil execution, file system access to sensitive AD database files, and the creation of NTDS backup directories.

## What This Dataset Contains

This dataset captures a failed attempt to use NTDSUtil for credential dumping. The key evidence appears in Security event 4688, which shows the command execution:

`"cmd.exe" /c mkdir C:\Windows\Temp\ntds_T1003 & ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\ntds_T1003" q q`

This command attempts to:
1. Create a temporary directory `C:\Windows\Temp\ntds_T1003`
2. Launch ntdsutil with "activate instance ntds" command
3. Use the "ifm" (Install From Media) mode to create a full backup to the temporary directory

However, the Security event 4689 shows this cmd.exe process exited with status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender or system protections blocked the operation.

The PowerShell events contain only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) without any technique-specific PowerShell code. The execution appears to have been performed through direct command execution rather than PowerShell scripting.

Sysmon events show normal PowerShell startup activity (DLL loading, pipe creation) but notably lack any ProcessCreate events for ntdsutil.exe itself, confirming the technique was blocked before ntdsutil could execute.

## What This Dataset Does Not Contain

This dataset is missing several critical elements that would be present in a successful NTDS dumping attack:

- No ProcessCreate events for ntdsutil.exe execution (blocked by Windows Defender)
- No file creation events for NTDS.dit or SYSTEM hive backup files
- No directory creation events for the target backup folder
- No registry access events related to SYSTEM hive reading
- No process access events showing interaction with domain controller services
- No network activity related to accessing remote NTDS databases

The lack of these events is due to Windows Defender's real-time protection blocking the ntdsutil execution before it could perform any meaningful credential dumping operations. This represents attempt telemetry rather than successful execution telemetry.

## Assessment

This dataset provides moderate value for detection engineering, primarily demonstrating the command-line signatures of NTDS dumping attempts and the telemetry available when endpoint protection successfully blocks the technique. The Security 4688 event with the full command line is the most valuable detection artifact, showing the complete ntdsutil syntax including the "ifm" command and target directory.

However, the dataset's utility is limited by the blocked execution. Detection engineers need examples of successful NTDS dumping to understand the full attack lifecycle, including file system artifacts, registry access patterns, and the specific process behaviors that occur during database extraction. The dataset would be stronger with either a successful execution example or additional failed attempts showing different ntdsutil command variations.

The privilege escalation telemetry (Security 4703) showing SeBackupPrivilege and SeRestorePrivilege being enabled is valuable, as these privileges are typically required for NTDS access and could serve as an early warning indicator.

## Detection Opportunities Present in This Data

1. **NTDSUtil Command Line Detection** - Monitor Security 4688 events for command lines containing "ntdsutil" with "ifm" or "create full" parameters, indicating NTDS database backup attempts.

2. **Suspicious Directory Creation for NTDS Storage** - Alert on cmd.exe creating directories with NTDS-related naming patterns (containing "ntds", "backup", or similar) in temporary locations.

3. **Process Exit Status Monitoring** - Track cmd.exe processes exiting with STATUS_ACCESS_DENIED (0xC0000022) when executing database utilities, indicating blocked credential dumping attempts.

4. **Privilege Escalation for Backup Operations** - Monitor Security 4703 events showing SeBackupPrivilege and SeRestorePrivilege being enabled, particularly when followed by database utility execution attempts.

5. **PowerShell Process Ancestry with Database Tools** - Detect PowerShell processes spawning cmd.exe children that attempt to execute ntdsutil, indicating scripted credential dumping automation.

6. **Failed Administrative Tool Execution** - Correlate Windows Defender blocks with command lines containing administrative database utilities to identify sophisticated credential access attempts.
