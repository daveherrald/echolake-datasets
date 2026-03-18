# T1112-83: Modify Registry — Modify UsePartialEncryptionKey Registry entry

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries modify Windows registry entries to disable security features, alter system behavior, or maintain persistence. The specific test in this dataset targets the `UsePartialEncryptionKey` registry value under `HKLM\SOFTWARE\Policies\Microsoft\FVE` (Full Volume Encryption/BitLocker). When set to 2, this value allows BitLocker to use partial encryption keys, potentially weakening disk encryption security. Adversaries may modify this setting to facilitate data exfiltration or to weaken encryption on compromised systems. Detection engineering typically focuses on monitoring registry modifications to security-related keys, especially those affecting encryption, Windows Defender, UAC, or authentication mechanisms.

## What This Dataset Contains

This dataset captures a successful registry modification executed via PowerShell calling cmd.exe, which then invokes reg.exe. The attack chain is clearly visible in both Sysmon and Security event logs:

**Process Chain**: PowerShell → cmd.exe → reg.exe
- Security 4688 shows cmd.exe creation with command line: `"cmd.exe" /c reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UsePartialEncryptionKey /t REG_DWORD /d 2 /f`
- Security 4688 shows reg.exe creation with command line: `reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UsePartialEncryptionKey /t REG_DWORD /d 2 /f`
- Sysmon EID 1 events capture both process creations with full command lines and parent process relationships

**Sysmon Coverage**: 37 events including process creation (EID 1), image loads (EID 7), process access (EID 10), file creation (EID 11), and pipe creation (EID 17). The reg.exe process is captured with RuleName "technique_id=T1012,technique_name=Query Registry" indicating the sysmon-modular config correctly identifies registry tooling.

**Security Events**: 12 events showing complete process lifecycle with 4688 (process creation) and 4689 (process termination) events, plus privilege adjustment (4703) showing PowerShell gaining extensive system privileges including SeBackupPrivilege and SeRestorePrivilege.

**PowerShell Telemetry**: 34 events but only containing test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no evidence of the actual registry modification commands.

## What This Dataset Does Not Contain

This dataset lacks the most critical telemetry for T1112 detection - **registry modification events**. There are no Security 4657 (registry value accessed) or 5136 (directory service object modified) events, and no Sysmon EID 12/13/14 (registry events). This is likely because the audit policy doesn't include object access auditing for registry keys, as indicated by `object_access: none` in the configuration. The successful completion (exit code 0x0 for all processes) indicates Windows Defender didn't block the operation, but the absence of registry telemetry significantly limits detection opportunities focused on the actual registry change rather than just the process execution.

The PowerShell script block logging also doesn't capture the Invoke-Expression or similar commands that would have executed the registry modification, suggesting the test used direct .NET calls or other methods that bypassed PowerShell's script block logging.

## Assessment

This dataset provides excellent process-level telemetry for detecting T1112 via command-line analysis but lacks the registry-specific events that would enable detection of the actual modification. The Security 4688 events with command-line logging provide the strongest detection value, clearly showing the intent to modify the specific BitLocker registry key. The Sysmon process creation events add valuable parent-child process relationships and file hashes. However, without registry modification events, defenders cannot confirm the registry change actually occurred or build detections around registry access patterns. For a complete T1112 detection capability, this dataset would need object access auditing enabled for registry keys.

## Detection Opportunities Present in This Data

1. **Command Line Analysis**: Security 4688 events contain explicit registry modification commands targeting `HKLM\SOFTWARE\Policies\Microsoft\FVE\UsePartialEncryptionKey` - high-fidelity indicator for BitLocker policy tampering

2. **Process Chain Analysis**: Sysmon EID 1 events show suspicious PowerShell → cmd.exe → reg.exe execution chain, particularly valuable when PowerShell invokes registry modification tools

3. **Registry Tool Execution**: Sysmon process creation events capture reg.exe execution with RuleName indicating registry operations - useful for detecting any registry modification tooling

4. **Privilege Escalation Context**: Security 4703 shows PowerShell acquiring backup/restore privileges before registry operations, indicating potential preparation for sensitive registry modifications

5. **Parent Process Analysis**: Sysmon parent process fields enable detection of scripting engines (PowerShell) spawning system administration tools for registry manipulation

6. **File Hash Indicators**: Sysmon events provide SHA256/MD5/IMPHASH values for reg.exe and cmd.exe, enabling allowlist validation to detect process hollowing or masquerading attempts

7. **BitLocker Policy Targeting**: Command line specifically targets Full Volume Encryption policies, enabling focused detection rules for encryption bypass attempts
