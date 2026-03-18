# T1112-82: Modify Registry — Modify EnableNonTPM Registry entry

## Technique Context

T1112 (Modify Registry) is a fundamental technique attackers use to achieve persistence, defense evasion, and system configuration changes. The EnableNonTPM registry modification specifically targets Windows BitLocker policies, allowing full volume encryption on systems without a Trusted Platform Module (TPM). This particular modification is significant because it can enable attackers to use BitLocker encryption for data protection after compromise, potentially complicating incident response and forensic analysis. The technique involves writing to `HKLM\SOFTWARE\Policies\Microsoft\FVE\EnableNonTPM` with a DWORD value of 1, which configures the system to allow BitLocker without hardware TPM requirements. Detection engineers typically focus on monitoring registry modifications to sensitive policy locations, especially those affecting encryption and security controls.

## What This Dataset Contains

The dataset captures a complete process execution chain starting with PowerShell and culminating in registry modification via reg.exe. The primary evidence includes:

**Process Chain**: PowerShell spawns cmd.exe with the command line `"cmd.exe" /c reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v EnableNonTPM /t REG_DWORD /d 1 /f`, which then spawns reg.exe with `reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v EnableNonTPM /t REG_DWORD /d 1 /f`.

**Security Events**: EID 4688 captures process creation for whoami.exe, cmd.exe, and reg.exe with complete command lines. EID 4703 shows privilege adjustment for PowerShell, enabling multiple high-privilege rights including SeBackupPrivilege and SeRestorePrivilege.

**Sysmon Events**: EID 1 captures process creation for whoami.exe, cmd.exe, and reg.exe with detailed metadata including process GUIDs, parent relationships, and file hashes. EID 10 shows PowerShell accessing both spawned processes with full access rights (0x1FFFFF).

**PowerShell Telemetry**: Contains only test framework boilerplate with Set-StrictMode and Set-ExecutionPolicy Bypass commands - no script block content related to the actual registry modification.

## What This Dataset Does Not Contain

Notably absent is any Sysmon EID 13 (Registry Value Set) event that would directly show the registry modification operation. This suggests either the sysmon-modular configuration filters out this registry location, or the reg.exe process completed successfully but the registry write event wasn't captured for another reason. There's also no PowerShell script block logging of the actual registry modification command, indicating the technique was executed via cmd.exe rather than native PowerShell registry cmdlets. No network activity or file system artifacts beyond process creation are captured.

## Assessment

This dataset provides excellent coverage of the process execution chain leading to registry modification, with strong process lineage tracking through both Security and Sysmon logs. The command-line capture is complete and provides clear evidence of intent. However, the lack of registry modification telemetry (Sysmon EID 13) is a significant gap - you can see the attempt but not the actual registry change. The dataset excels at demonstrating process-based detection opportunities but falls short of confirming technique success. For detection engineering focused on process execution patterns and command-line analysis, this data is highly valuable. For detecting actual registry state changes, additional logging would be needed.

## Detection Opportunities Present in This Data

1. **Command-line pattern matching** - Detect `reg.exe` execution with "HKLM\SOFTWARE\Policies\Microsoft\FVE" and "EnableNonTPM" parameters
2. **Process chain analysis** - Monitor PowerShell spawning cmd.exe spawning reg.exe, particularly when targeting policy registry locations
3. **BitLocker policy modification** - Alert on any process attempting to modify FVE (Full Volume Encryption) policy keys
4. **Privilege escalation context** - Correlate registry modification attempts with processes holding SeBackupPrivilege and SeRestorePrivilege
5. **Parent-child process relationships** - Flag reg.exe launched by cmd.exe launched by PowerShell as potentially suspicious automation
6. **System-level registry modifications** - Monitor SYSTEM account processes modifying HKLM policy locations outside of expected administrative tools
7. **Registry tool abuse** - Detect reg.exe usage with force flags (/f) when modifying encryption-related policies
