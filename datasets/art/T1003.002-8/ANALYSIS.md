# T1003.002-8: Security Account Manager — Dumping of SAM, creds, and secrets(Reg Export)

## Technique Context

T1003.002 Security Account Manager focuses on extracting credential information from the Windows SAM database, which stores local user account password hashes and related security data. Attackers commonly target SAM along with SECURITY and SYSTEM registry hives to obtain password hashes for offline cracking or pass-the-hash attacks. The reg.exe export method is a straightforward technique that requires SYSTEM-level privileges but produces easily detectable registry operations.

Detection engineers focus on monitoring reg.exe execution with export operations targeting sensitive hives (SAM, SECURITY, SYSTEM), file creation events for exported registry files, and process chains involving these operations. This technique is particularly valuable for attackers because it provides local credential material without needing to interact with LSASS directly, making it potentially less likely to trigger memory-based detections.

## What This Dataset Contains

This dataset captures a successful SAM database export operation using reg.exe commands. The attack chain begins with PowerShell execution and proceeds through the following process hierarchy:

- **Initial PowerShell session**: Process ID 5752 (`powershell.exe`) running as NT AUTHORITY\SYSTEM
- **Command shell invocation**: Security 4688 shows cmd.exe (PID 6556) with command line `"cmd.exe" /c reg export HKLM\sam %temp%\sam & reg export HKLM\system %temp%\system & reg export HKLM\security %temp%\security`
- **Sequential registry exports**: Three separate reg.exe processes export the critical hives:
  - PID 6388: `reg export HKLM\sam C:\Windows\TEMP\sam`
  - PID 5240: `reg export HKLM\system C:\Windows\TEMP\system` 
  - PID 6948: `reg export HKLM\security C:\Windows\TEMP\security`

Sysmon captures the complete process creation chain with EID 1 events for whoami.exe, cmd.exe, and all three reg.exe instances. File creation events (Sysmon EID 11) show the exported registry files being written to `C:\Windows\Temp\` along with temporary files in `C:\Windows\SystemTemp\`. All processes execute with System integrity level and show successful completion (exit status 0x0 in Security 4689 events).

## What This Dataset Does Not Contain

The dataset shows successful technique execution without any blocking or interference from Windows Defender, despite real-time protection being active. The technique completed successfully, creating all three exported registry files. The PowerShell channel contains only framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual command execution, as the technique was likely invoked through a different execution method. No Sysmon ProcessCreate events are captured for the parent PowerShell process that initiated the attack, indicating the sysmon-modular config's include-mode filtering didn't match powershell.exe as a suspicious pattern in this context.

## Assessment

This dataset provides excellent telemetry for detecting SAM database export attacks. The Security audit policy captures complete command-line information for all processes involved, while Sysmon provides detailed process creation, file creation, and process access events. The combination of Security 4688 events with full command lines and Sysmon EID 1 events with parent process relationships creates a comprehensive view of the attack chain. The file creation events definitively show the technique's success, providing both behavioral indicators (reg.exe export commands) and artifact indicators (exported SAM/SECURITY/SYSTEM files).

The data quality is particularly strong because it demonstrates the technique executing in a realistic privileged context without EDR interference, showing exactly what defenders should expect to see when this technique succeeds in their environment.

## Detection Opportunities Present in This Data

1. **Registry export command detection**: Security 4688 events show reg.exe processes with command lines containing "export HKLM\sam", "export HKLM\system", and "export HKLM\security" - classic indicators of credential harvesting attempts.

2. **Sensitive registry hive targeting**: Multiple reg.exe processes targeting the three critical Windows credential storage hives (SAM, SECURITY, SYSTEM) within a short time window indicates systematic credential extraction.

3. **File creation in temporary directories**: Sysmon EID 11 events show registry export files being created in `C:\Windows\Temp\` with filenames matching the exported hives, providing definitive proof of technique success.

4. **Process chain analysis**: The progression from PowerShell → cmd.exe → multiple reg.exe processes with credential-related arguments represents a common attack pattern for SAM database extraction.

5. **Command shell with registry export operations**: The cmd.exe command line containing multiple registry export operations chained with ampersands (`&`) is a clear behavioral signature of automated credential harvesting.

6. **System-level registry access**: All processes executing with NT AUTHORITY\SYSTEM privileges while performing registry export operations indicates potential privilege escalation or system compromise for credential access.
