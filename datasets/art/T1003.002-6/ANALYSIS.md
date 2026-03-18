# T1003.002-6: Security Account Manager — dump volume shadow copy hives with System.IO.File

## Technique Context

T1003.002 (Security Account Manager) involves extracting credential data from the Windows SAM database, which stores local user account credentials including NTLM password hashes. Attackers commonly target this technique for credential harvesting to enable lateral movement and privilege escalation.

This specific test attempts to use .NET's System.IO.File class to copy the SAM hive from Volume Shadow Copy (VSC) paths. Volume Shadow Copies provide point-in-time snapshots of system volumes and can bypass file locks that normally protect the SAM database from access by running processes. The technique leverages the `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*` path format to access VSC snapshots directly, attempting to iterate through shadow copies 1-10 and extract SAM files to %TEMP%.

Detection engineers focus on monitoring for VSC access patterns, suspicious file operations targeting credential stores, and the specific GLOBALROOT path syntax used to bypass normal file system protections.

## What This Dataset Contains

The primary evidence appears in Security event 4688, showing a PowerShell process created with command line: `"powershell.exe" & {1..10 | % { try { [System.IO.File]::Copy(\"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy$_\Windows\System32\config\SAM\" , \"$env:TEMP\SAMvss$_\", \"true\") } catch {} ls \"$env:TEMP\SAMvss$_\" -ErrorAction Ignore}}`. This command attempts to iterate through VSC instances 1-10, copying SAM files to temp directory locations like `SAMvss1`, `SAMvss2`, etc.

The technique was blocked by Windows security controls - the PowerShell process exits with status code 0xC0000022 (STATUS_ACCESS_DENIED), indicating Windows Defender or system protections prevented the VSC access or file operations.

Sysmon provides complementary process tracking with events showing PowerShell startup (EID 1 for whoami.exe execution, EID 7 for .NET runtime loading, EID 17 for named pipe creation). The dataset captures the process creation chain but lacks Sysmon ProcessCreate events for the main PowerShell processes due to the sysmon-modular include-mode filtering.

Security EID 4703 shows privilege escalation with SeBackupPrivilege and SeRestorePrivilege being enabled, which are commonly required for VSC operations and credential extraction attempts.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful SAM file extraction since Windows security controls blocked the operation. No Sysmon FileCreate events (EID 11) show SAM files being written to %TEMP% locations, and no successful file access to VSC paths is captured.

The sysmon-modular configuration filtered out the main PowerShell ProcessCreate events since powershell.exe doesn't match the include-mode suspicious patterns. This means the initial PowerShell execution that launched the attack command is only visible in Security 4688 events, not Sysmon EID 1.

No network activity, registry modifications, or additional credential access attempts are present since the technique was blocked before file operations could complete. The PowerShell script block logging only contains test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual malicious command content.

## Assessment

This dataset effectively demonstrates a blocked credential access attempt with strong coverage of the security control response. The Security channel captures both the malicious command line and the access denied outcome, providing clear evidence of the attack attempt and its mitigation.

The combination of Security 4688 command-line logging and privilege escalation events (4703) provides sufficient detail for detection engineering, even without successful file operations. However, the filtered Sysmon ProcessCreate events limit the granular process tree visibility that would normally be available for this type of PowerShell-based attack.

For detection development, this represents a realistic scenario where modern endpoint protection successfully prevents credential extraction while still generating valuable telemetry about the attempt.

## Detection Opportunities Present in This Data

1. **VSC Path Access Patterns** - Monitor command lines containing `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy` syntax in Security 4688 events, particularly when combined with credential store paths like `\Windows\System32\config\SAM`

2. **System.IO.File SAM Copying** - Detect PowerShell commands using .NET System.IO.File.Copy methods targeting SAM, SYSTEM, or SECURITY hive files from VSC locations

3. **Privilege Escalation for VSC Operations** - Alert on Security 4703 events showing SeBackupPrivilege and SeRestorePrivilege enablement, especially when followed by file system operations targeting credential stores

4. **Iterative VSC Enumeration** - Identify command patterns that loop through numbered VSC instances (e.g., `1..10 | %`) combined with credential file access attempts

5. **PowerShell Exit Code Analysis** - Monitor for PowerShell processes terminating with STATUS_ACCESS_DENIED (0xC0000022) after attempting credential-related operations, indicating blocked attack attempts

6. **Temp Directory SAM Staging** - Watch for file operations attempting to create files matching patterns like `SAMvss*` in user temp directories, even when blocked by security controls
