# T1222-3: File and Directory Permissions Modification — Enable Local and Remote Symbolic Links via Powershell

## Technique Context

T1222 (File and Directory Permissions Modification) involves adversaries altering permissions on files and directories to enable access control bypass or persistence. Specifically, T1222.003 focuses on modifying Windows NTFS permissions and access control lists. This particular test targets symbolic link policies via registry modification, which can enable attackers to create symbolic links that bypass access controls or facilitate lateral movement. The technique is commonly used for defense evasion, allowing malicious code to access resources it normally couldn't reach. Detection engineers typically monitor for suspicious permission changes, especially those affecting critical system directories or involving privilege escalation patterns.

## What This Dataset Contains

The dataset captures a PowerShell-based attempt to enable local and remote symbolic link evaluation through registry modifications. The core technique is visible in Security event 4688, showing the PowerShell command line:

`"powershell.exe" & {New-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\Filesystems\NTFS -Name SymlinkRemoteToLocalEvaluation -PropertyType DWORD -Value 1 -Force -ErrorAction Ignore New-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\Filesystems\NTFS -Name SymlinkRemoteToRemoteEvaluation -PropertyType DWORD -Value 1 -Force -ErrorAction Ignore}`

PowerShell events 4103 show the actual cmdlet invocations with detailed parameter bindings, including the target registry path `HKLM:\Software\Policies\Microsoft\Windows\Filesystems\NTFS` and the specific values being set. Critically, both 4103 events show `NonTerminatingError(New-ItemProperty): "Cannot find path 'HKLM:\Software\Policies\Microsoft\Windows\Filesystems\NTFS' because it does not exist."`, indicating the technique failed because the required registry path doesn't exist.

Sysmon captures the process creation (EID 1) for both the parent PowerShell process and the child PowerShell process executing the registry modifications. Process access events (EID 10) show PowerShell accessing both the whoami.exe process and the child PowerShell process with full access rights (0x1FFFFF). The Security channel provides comprehensive process creation and termination telemetry (4688/4689) with full command lines.

## What This Dataset Does Not Contain

The dataset lacks registry modification events because the technique failed - the target registry path didn't exist. No Sysmon EID 13 (RegistryEvent) or EID 12 (RegistryEvent) events are present, which would normally capture successful registry value creation. The PowerShell events confirm the failure with explicit error messages stating the path doesn't exist. Additionally, there are no successful symbolic link creation events or file system permission changes, as the prerequisite registry modifications never occurred. The error handling (`-ErrorAction Ignore`) prevented PowerShell from terminating, but also means no dramatic failure telemetry beyond the error messages in the command invocation logs.

## Assessment

This dataset provides excellent visibility into a failed T1222 technique execution. The Security 4688 events with command-line auditing capture the complete attack intent, while PowerShell 4103 events provide granular detail about the specific registry modifications attempted. The combination of process creation telemetry and detailed PowerShell logging creates strong detection opportunities even for failed attempts. However, the dataset's value is somewhat limited for understanding successful symbolic link policy modifications since the technique failed at the prerequisite registry path creation stage. For building robust detections, this data is valuable for identifying attempt patterns, but analysts would need additional datasets showing successful executions to understand the complete attack lifecycle.

## Detection Opportunities Present in This Data

1. **PowerShell Registry Modification Targeting Symbolic Link Policies** - Monitor Security 4688 and PowerShell 4103/4104 events for New-ItemProperty cmdlets targeting `HKLM:\Software\Policies\Microsoft\Windows\Filesystems\NTFS` with `SymlinkRemoteToLocalEvaluation` or `SymlinkRemoteToRemoteEvaluation` parameters.

2. **Failed Registry Path Access Patterns** - Alert on PowerShell error messages indicating "Cannot find path" for security-sensitive registry locations, particularly those related to filesystem policies.

3. **PowerShell Command Line Pattern Matching** - Detect command lines containing both `SymlinkRemoteToLocalEvaluation` and `SymlinkRemoteToRemoteEvaluation` registry value names, regardless of execution success.

4. **Suspicious PowerShell Parameter Combinations** - Monitor for New-ItemProperty cmdlets with `-Force` and `-ErrorAction Ignore` parameters when targeting system policy registry locations.

5. **Process Tree Analysis for Registry Modification Attempts** - Correlate parent-child PowerShell processes (visible in Sysmon EID 1 and Security 4688) executing registry modification commands targeting filesystem policies.
