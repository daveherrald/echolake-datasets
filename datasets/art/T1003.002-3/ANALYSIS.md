# T1003.002-3: Security Account Manager — esentutl.exe SAM copy

## Technique Context

T1003.002 (Security Account Manager) is a credential access technique where attackers extract credential material from the Windows Security Account Manager (SAM) database. The SAM contains password hashes for local user accounts and is a primary target for credential harvesting on Windows systems. This specific test uses `esentutl.exe`, a legitimate Windows utility for working with Extensible Storage Engine (ESE) databases, to copy the SAM file using Volume Shadow Service (VSS) capabilities.

The detection community focuses heavily on monitoring access to credential stores like the SAM database. Key detection points include: processes accessing the SAM file directly, use of backup utilities like `esentutl.exe` against system databases, Volume Shadow Copy operations involving credential stores, and unusual file creation in temporary directories with names matching credential databases. The technique is particularly dangerous because it uses legitimate Windows utilities (Living off the Land), making behavioral detection crucial.

## What This Dataset Contains

This dataset captures a successful SAM database extraction using `esentutl.exe` with VSS integration. The core attack chain is clearly visible in the process creation events:

- **Security 4688**: PowerShell spawns `cmd.exe` with command line `"cmd.exe" /c esentutl.exe /y /vss %SystemRoot%/system32/config/SAM /d %temp%/SAM`
- **Security 4688**: cmd.exe spawns `esentutl.exe` with command line `esentutl.exe /y /vss C:\Windows/system32/config/SAM /d C:\Windows\TEMP/SAM`
- **Sysmon 1**: Process creation for esentutl.exe with the same command line parameters

The dataset shows extensive VSS activity through registry modifications. **Sysmon 13** events document the complete VSS workflow with registry writes to `HKLM\System\CurrentControlSet\Services\VSS\Diag\*` keys, including writer identification, backup preparation, snapshot operations, and completion phases.

**Sysmon 11** captures the critical file creation event: `C:\Windows\Temp\SAM` created by esentutl.exe process 820, confirming successful SAM database extraction to the temporary directory.

**Security 4703** events show token privilege adjustments for the VSSVC.exe process, including enabling `SeBackupPrivilege` and `SeRestorePrivilege` - privileges required for VSS operations.

## What This Dataset Does Not Contain

The dataset lacks several important detection opportunities. There are no **Sysmon 15** (FileCreateStreamHash) events for the extracted SAM file, which would provide hash verification of the credential database copy. No **Security 4656/4658** object access events are present, likely because detailed object access auditing wasn't enabled for the SAM file location.

More critically, there are no follow-on activities showing what an attacker would typically do next - no process creation events for credential extraction tools like Mimikatz or hashcat, no network connections suggesting credential database exfiltration, and no file deletion events showing cleanup of the extracted SAM file.

The PowerShell logs contain only test framework boilerplate with Set-ExecutionPolicy commands, lacking any script block content that might reveal the PowerShell commands used to orchestrate the attack.

## Assessment

This dataset provides excellent telemetry for detecting esentutl.exe-based SAM extraction. The process creation chain is completely captured with full command lines, making command-line based detection straightforward. The extensive Sysmon 13 registry events offer multiple opportunities for detecting VSS abuse patterns, particularly the characteristic registry activity under the VSS diagnostic keys.

The file creation event for the extracted SAM database is the smoking gun - direct evidence of credential database theft. The combination of process telemetry, VSS registry activity, and file creation provides multiple independent detection vectors that would be difficult for attackers to evade simultaneously.

However, the dataset's utility is somewhat limited by the lack of post-extraction activity and the absence of object access logging. Real-world detection would benefit from seeing the complete attack lifecycle and having file access events for the source SAM database.

## Detection Opportunities Present in This Data

1. **Command-line detection**: Monitor for `esentutl.exe` execution with `/y` and `/vss` parameters combined with paths to credential databases (`SAM`, `SYSTEM`, `SECURITY`)

2. **VSS registry activity**: Alert on registry writes to `HKLM\System\CurrentControlSet\Services\VSS\Diag\*` keys when initiated by non-backup processes or occurring outside maintenance windows

3. **Credential database file creation**: Monitor file creation events where filename equals `SAM`, `SYSTEM`, or `SECURITY` in temporary directories (`%temp%`, `C:\Windows\Temp`)

4. **Process chain analysis**: Detect esentutl.exe spawned by cmd.exe or PowerShell with database-related parameters, especially when the parent process wasn't initiated by backup software

5. **Privilege escalation correlation**: Correlate Security 4703 events showing SeBackupPrivilege/SeRestorePrivilege enabling with subsequent esentutl.exe execution

6. **Parent-child process relationship**: Flag esentutl.exe processes with unusual parent processes (PowerShell, cmd.exe) rather than legitimate backup applications

7. **VSS writer enumeration**: Monitor for rapid sequential registry access to multiple VSS writer identification keys, which may indicate automated credential harvesting preparation
