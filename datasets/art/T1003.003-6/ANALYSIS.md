# T1003.003-6: NTDS — Create Volume Shadow Copy remotely (WMI) with esentutl

## Technique Context

T1003.003 (NTDS) involves extracting credential material from the Active Directory database (ntds.dit), which contains password hashes for all domain accounts. This technique is a high-value target for attackers seeking to move laterally or escalate privileges in domain environments. The specific variant in this test attempts to use WMI to remotely create a volume shadow copy and then extract the NTDS database using esentutl.exe, a legitimate Windows utility for managing Extensible Storage Engine (ESE) databases.

The detection community focuses on monitoring for unusual access to domain controller files, volume shadow copy creation, and the abuse of legitimate utilities like esentutl.exe with specific command-line patterns targeting ntds.dit. This technique represents a critical point in attack chains where defenders must detect credential harvesting attempts before attackers can dump domain password hashes.

## What This Dataset Contains

The dataset captures a failed attempt to extract the NTDS database using WMI and esentutl. The core attack chain shows in Security event 4688:

1. PowerShell spawns cmd.exe with: `"cmd.exe" /c wmic /node:"localhost" process call create "cmd.exe /c esentutl.exe /y /vss c:\windows\ntds\ntds.dit /d c:\ntds.dit"`
2. WMIC.exe is created with: `wmic /node:"localhost" process call create "cmd.exe /c esentutl.exe /y /vss c:\windows\ntds\ntds.dit /d c:\ntds.dit"`
3. WmiPrvSE.exe spawns cmd.exe with: `cmd.exe /c esentutl.exe /y /vss c:\windows\ntds\ntds.dit /d c:\ntds.dit`
4. Finally, esentutl.exe executes with: `esentutl.exe /y /vss c:\windows\ntds\ntds.dit /d c:\ntds.dit`

The esentutl process exits with error code 0xFFFFF69D (Security event 4689), indicating the operation failed. Volume Shadow Copy Service errors appear in the Application log with "CoInitialize has not been called" messages, suggesting the VSS operation was unsuccessful. Sysmon captures the complete process creation chain with events tagged for T1047 (WMI), T1564.004 (NTDS File Attributes), and T1059.003 (Windows Command Shell).

## What This Dataset Does Not Contain

The dataset shows a failed technique execution - the ntds.dit file was not successfully extracted or copied. There are no file creation events for the target output file `c:\ntds.dit`, confirming the operation was unsuccessful. The Volume Shadow Copy creation failed, as evidenced by the Application log errors and the esentutl exit code. Since this is a workstation rather than a domain controller, the source path `c:\windows\ntds\ntds.dit` likely doesn't exist, contributing to the failure. The dataset also lacks any network connections that might indicate successful exfiltration of credential data.

## Assessment

This dataset provides excellent telemetry for detecting NTDS extraction attempts, even when they fail. The Security event 4688 logs with full command-line auditing capture the complete attack chain from PowerShell through WMI to esentutl execution. Sysmon's process creation events (EID 1) with technique tagging provide additional context and detection opportunities. The combination of WMI process creation, esentutl usage with specific parameters, and Volume Shadow Copy operations creates a strong detection signature. While the technique failed in this instance, the telemetry demonstrates what defenders should monitor for in environments where such attacks might succeed.

## Detection Opportunities Present in This Data

1. **esentutl.exe execution with NTDS-specific parameters** - Monitor Sysmon EID 1 and Security EID 4688 for esentutl.exe with `/y /vss` and `ntds.dit` in the command line
2. **WMI remote process creation targeting credential extraction tools** - Detect WMIC.exe creating processes with esentutl.exe or other database utilities
3. **Volume Shadow Copy operations combined with credential access tools** - Correlate VSS errors in Application logs with esentutl or vssadmin execution
4. **Process chain analysis for credential dumping** - Alert on PowerShell → cmd.exe → wmic.exe → WmiPrvSE.exe → cmd.exe → esentutl.exe chains
5. **Privilege escalation to SYSTEM context for credential access** - Monitor Security EID 4703 token right adjustments combined with credential access tool execution
6. **Suspicious file path targeting in esentutl operations** - Flag esentutl.exe operations targeting `c:\windows\ntds\` or attempting to copy `ntds.dit` to accessible locations
7. **WMI process creation with credential access patterns** - Detect WMI-spawned processes attempting to access domain controller database files
