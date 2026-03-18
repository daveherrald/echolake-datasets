# T1112-77: Modify Registry — Modify EnableBDEWithNoTPM Registry entry

## Technique Context

T1112 (Modify Registry) is a fundamental technique used by attackers to establish persistence, modify system configurations, disable security controls, and alter system behavior. The specific test modifies the `EnableBDEWithNoTPM` registry value, which controls BitLocker Drive Encryption policy when no Trusted Platform Module (TPM) is present. This modification allows BitLocker encryption without hardware TPM requirements, potentially weakening the security posture of encrypted drives.

Adversaries commonly target registry modifications to disable security features, create backdoors, or modify system configurations to support their operations. The detection community focuses on monitoring registry writes to sensitive locations, particularly those affecting security policies, startup locations, and system configurations. The `HKLM\SOFTWARE\Policies\Microsoft\FVE` path specifically controls Full Volume Encryption (BitLocker) policies.

## What This Dataset Contains

This dataset captures the complete execution chain of the registry modification technique:

**Process Chain**: PowerShell → cmd.exe → reg.exe
- Sysmon EID 1 shows PowerShell (PID 33016) spawning cmd.exe with command line: `"cmd.exe" /c reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v EnableBDEWithNoTPM /t REG_DWORD /d 1 /f`
- Sysmon EID 1 shows cmd.exe (PID 29972) spawning reg.exe with command line: `reg  add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v EnableBDEWithNoTPM /t REG_DWORD /d 1 /f`

**Security Events**: Comprehensive process lifecycle tracking
- Security EID 4688 events show process creation with full command lines
- Security EID 4689 events show clean process termination (exit status 0x0)
- Security EID 4703 shows PowerShell token privilege adjustment including `SeBackupPrivilege` and `SeRestorePrivilege`

**PowerShell Activity**: The PowerShell channel contains only boilerplate test framework activity
- Multiple EID 4104 script block events showing `Set-StrictMode` error handling templates
- EID 4103 showing `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`

**Sysmon Coverage**: Rich process and DLL loading telemetry
- Process creation events with full hashes and parent relationships
- Image load events (EID 7) showing .NET runtime and PowerShell module loading
- Process access events (EID 10) with call traces showing PowerShell accessing child processes

## What This Dataset Does Not Contain

**Registry Modification Events**: Notably absent are Sysmon EID 13 (Registry value set) events. The sysmon-modular configuration may not be capturing this specific registry path, or the events were filtered out. This is a significant gap since the actual registry write is the core technique behavior.

**Object Access Events**: No Security EID 4657 (Registry value modified) events, indicating object access auditing is not enabled for registry operations.

**Network Activity**: No network connections or DNS queries related to this technique, as expected for a local registry modification.

**File System Activity**: Only PowerShell startup profile files are created; no malicious file drops or modifications.

## Assessment

This dataset provides strong coverage of the process execution chain and command-line arguments but lacks the most critical telemetry: the actual registry modification events. While you can detect the technique through process creation and command-line analysis, the absence of registry-specific events (Sysmon EID 13 or Security EID 4657) reduces the dataset's value for demonstrating complete registry monitoring.

The Security channel's process creation events with command-line logging provide excellent coverage for building detection rules based on the reg.exe execution pattern. The Sysmon process creation events include rich metadata like file hashes and parent-child relationships that enhance detection fidelity.

## Detection Opportunities Present in This Data

1. **Registry Tool Execution**: Security EID 4688 events showing `reg.exe` with command line containing `add`, `HKLM\SOFTWARE\Policies\Microsoft\FVE`, and `EnableBDEWithNoTPM` parameters

2. **PowerShell Command Execution Chain**: Sysmon EID 1 events showing PowerShell spawning cmd.exe with `/c reg add` pattern, indicating indirect registry modification

3. **BitLocker Policy Modification**: Command line analysis detecting modifications to FVE (Full Volume Encryption) policy registry paths

4. **Suspicious Process Ancestry**: Process chain of PowerShell → cmd.exe → reg.exe running as SYSTEM, which may indicate automated or scripted policy modification

5. **Registry Tool with Force Flag**: Detection of `reg.exe` execution with `/f` (force) parameter combined with policy modification paths

6. **Administrative Registry Modification**: Security EID 4703 token privilege adjustment showing `SeBackupPrivilege` and `SeRestorePrivilege` escalation before registry operations

7. **System Account Registry Changes**: Process creation events showing SYSTEM account performing registry modifications to security-relevant policy paths
