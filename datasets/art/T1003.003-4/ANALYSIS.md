# T1003.003-4: NTDS — Create Volume Shadow Copy with WMI

## Technique Context

T1003.003 (NTDS) involves extracting credential material from the Windows NT Directory Services (NTDS) database, which stores Active Directory credentials including password hashes for domain accounts. This technique is critical for attackers seeking to escalate privileges and move laterally within domain environments. The NTDS.dit file contains NTLM hashes, Kerberos keys, and other sensitive authentication data that can enable pass-the-hash attacks or credential cracking.

This specific test (T1003.003-4) demonstrates using Volume Shadow Copy Service (VSS) via WMI to create a shadow copy of the system drive, which is a common prerequisite for accessing the locked NTDS.dit file. The detection community focuses heavily on monitoring shadow copy creation operations, particularly when initiated by non-backup processes, as this is a strong indicator of credential harvesting attempts.

## What This Dataset Contains

The dataset captures a successful Volume Shadow Copy creation via WMI with the following key telemetry:

**Process Chain**: PowerShell → cmd.exe → wmic.exe executing `wmic shadowcopy call create Volume=C:\`

**Security Events**: EID 4688 process creation events show the full command line: `"cmd.exe" /c wmic shadowcopy call create Volume=C:\` and `wmic shadowcopy call create Volume=C:\`

**Privilege Escalation**: EID 4703 events show WMIC.exe enabling critical privileges including `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeManageVolumePrivilege` - all required for shadow copy operations

**Sysmon Process Creation**: EID 1 events for whoami.exe (System Owner/User Discovery), cmd.exe (Windows Command Shell), with full command lines and process relationships

**Volume Shadow Copy Service Activity**: Extensive Sysmon EID 13 registry events from vssvc.exe showing the complete shadow copy creation workflow including provider operations (PROVIDER_BEGINPREPARE, PROVIDER_ENDPREPARE, PROVIDER_PRECOMMIT, etc.)

**WMI Process Activity**: Sysmon shows WMIC.exe loading urlmon.dll and amsi.dll, indicating legitimate WMI operations with AMSI scanning

## What This Dataset Does Not Contain

The dataset shows successful shadow copy creation but does not contain:

**NTDS.dit Access**: No file operations showing actual access to or copying of the NTDS.dit file from the shadow copy
**File Extraction**: No evidence of subsequent steps to extract credential data from the shadow copy
**Network Activity**: No network connections showing credential exfiltration
**Additional Tooling**: No evidence of tools like ntdsutil, vssadmin, or custom scripts to leverage the created shadow copy
**LSASS Interaction**: No process access events targeting LSASS, as this technique accesses the offline database copy

The technique execution appears to stop at shadow copy creation, which is typically just the first step in NTDS credential harvesting.

## Assessment

This dataset provides excellent telemetry for detecting Volume Shadow Copy creation as a precursor to NTDS credential harvesting. The Security log captures the essential command-line evidence and privilege escalation indicators, while Sysmon provides comprehensive process relationships and VSS service activity. The registry events from vssvc.exe offer detailed forensic artifacts of the shadow copy creation process.

The data quality is high for building detections around WMI-based shadow copy creation, privilege enumeration, and VSS service monitoring. However, the dataset's utility is limited for understanding complete NTDS extraction workflows since it only captures the preparatory shadow copy step.

## Detection Opportunities Present in This Data

1. **WMI Shadow Copy Creation**: Security EID 4688 with command line `wmic shadowcopy call create` from non-backup processes

2. **Critical Privilege Escalation**: Security EID 4703 showing WMIC.exe enabling SeBackupPrivilege, SeRestorePrivilege, and SeManageVolumePrivilege simultaneously

3. **Suspicious Process Chain**: Sysmon EID 1 showing PowerShell → cmd.exe → wmic.exe execution sequence for shadow copy operations

4. **VSS Service Registry Activity**: Sysmon EID 13 registry writes to VSS\Diag paths from vssvc.exe indicating shadow copy provider operations

5. **System Discovery Correlation**: Correlation of whoami.exe execution (T1033) with subsequent shadow copy creation indicating reconnaissance-to-collection progression

6. **WMI Process Anomalies**: WMIC.exe executing shadow copy commands outside of scheduled backup windows or from interactive sessions

7. **Volume-Specific Targeting**: WMI commands specifically targeting the C:\ volume where NTDS.dit typically resides on domain controllers
