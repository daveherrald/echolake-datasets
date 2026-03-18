# T1003.003-7: NTDS — Create Volume Shadow Copy with Powershell

## Technique Context

T1003.003 represents NTDS credential access — extracting password hashes from the Active Directory Domain Services database (ntds.dit). This technique is fundamental to lateral movement in domain environments, as the NTDS database contains password hashes for all domain accounts. Attackers typically use Volume Shadow Copy Service (VSS) to create a snapshot of the system volume, allowing them to access normally locked files like ntds.dit while the domain controller remains operational.

The detection community focuses heavily on Volume Shadow Copy creation events, WMI interactions with shadow copy classes, and subsequent access to the copied NTDS database. VSS operations require SYSTEM privileges and generate distinctive telemetry through both WMI calls and Windows VSS service activity.

## What This Dataset Contains

This dataset captures a successful PowerShell-based Volume Shadow Copy creation using the command `(gwmi -list win32_shadowcopy).Create('C:\','ClientAccessible')`. The key evidence includes:

**Security Events:** Process creation for the shadow copy PowerShell command with Security 4688: `"powershell.exe" & {(gwmi -list win32_shadowcopy).Create('C:\','ClientAccessible')}`, along with privilege escalation event 4703 showing PowerShell enabling high-privilege tokens including `SeBackupPrivilege` and `SeManageVolumePrivilege`.

**PowerShell Events:** Script block logging captured the WMI command execution in event 4104: `& {(gwmi -list win32_shadowcopy).Create('C:\','ClientAccessible')}` and module logging in 4103 showing `Get-WmiObject` with parameters `-List` and `-Class win32_shadowcopy`.

**Sysmon Events:** Process creation (EID 1) for the PowerShell execution, WMI library loading (EID 7) including `wmiutils.dll`, and extensive VSS service registry activity (EID 13) showing the complete shadow copy lifecycle from `PROVIDER_BEGINPREPARE` through `PROVIDER_POSTFINALCOMMIT`. The VSS service (vssvc.exe, PID 7080) generated 29 registry events documenting volume operations on `Volume{6e20c311-c974-475c-b1c6-c5882a662d13}`.

## What This Dataset Does Not Contain

The dataset shows Volume Shadow Copy creation but lacks evidence of actual NTDS database extraction. There are no file access events showing copying of ntds.dit, SYSTEM registry hive, or SAM database from the shadow copy volume. No network connections suggest exfiltration, and no additional tools like secretsdump.py or ntdsutil appear in the process chains. The technique execution appears to complete only the preparatory shadow copy creation step without the credential harvesting that would typically follow.

This workstation environment also means no actual NTDS database exists to extract — this technique would be more meaningful on a domain controller where ntds.dit contains domain credential hashes.

## Assessment

This dataset provides excellent telemetry for detecting the initial phases of T1003.003 attacks. The combination of command-line logging, WMI interaction monitoring, and VSS service registry tracking offers multiple detection vectors. Security teams can build robust detections around PowerShell WMI shadow copy commands, VSS service activity patterns, and privilege escalation events. However, analysts should note this captures only the setup phase — real-world detections should also monitor for subsequent file access to the shadow copy volume and potential credential database extraction activities.

## Detection Opportunities Present in This Data

1. **PowerShell WMI Shadow Copy Creation** - Security 4688 and PowerShell 4104 showing `(gwmi -list win32_shadowcopy).Create()` with drive letter parameters
2. **WMI Win32_ShadowCopy Class Enumeration** - PowerShell 4103 showing `Get-WmiObject` with `-List` parameter and `win32_shadowcopy` class
3. **High-Privilege Token Assignment** - Security 4703 showing PowerShell process enabling `SeBackupPrivilege` and `SeManageVolumePrivilege`
4. **VSS Service Registry Activity Pattern** - Sysmon 13 events from vssvc.exe showing sequential shadow copy operations from BEGINPREPARE through POSTFINALCOMMIT phases
5. **WMI Library Loading in PowerShell** - Sysmon 7 showing wmiutils.dll loading into powershell.exe processes
6. **Volume Shadow Copy Service State Changes** - Registry writes to `HKLM\System\CurrentControlSet\Services\VSS\Diag\` indicating active shadow copy operations
7. **PowerShell Process Chain for Shadow Copy** - Parent-child PowerShell relationship in Sysmon 1 with shadow copy command line arguments
