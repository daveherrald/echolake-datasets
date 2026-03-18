# T1112-50: Modify Registry — Enabling Remote Desktop Protocol via Remote Registry

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries alter Windows registry entries to change system behavior, disable security features, or maintain persistence. This specific test focuses on enabling Remote Desktop Protocol (RDP) by modifying the SecurityLayer registry value, which is a common technique used by attackers to establish remote access to compromised systems. The SecurityLayer setting controls RDP authentication requirements - setting it to 0 disables Network Level Authentication, making RDP connections easier to establish. Detection engineers focus on monitoring registry modifications to security-relevant keys, particularly those affecting remote access services like Terminal Services/RDP.

## What This Dataset Contains

This dataset captures a successful registry modification to enable RDP via the reg.exe utility. The core attack sequence shows:

**Process Chain**: PowerShell → cmd.exe → reg.exe with the command `reg add "hklm\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`

**Security 4688 Events**: Process creation for cmd.exe and reg.exe with full command lines showing the registry modification attempt. The reg.exe exit status is 0x0, indicating successful execution.

**Sysmon Process Creation (EID 1)**: Two processes captured - whoami.exe for reconnaissance and cmd.exe executing the registry modification command. The cmd.exe process shows the complete command line targeting the Terminal Server registry path.

**Sysmon Process Access (EID 10)**: PowerShell accessing both whoami.exe and cmd.exe processes with full access rights (0x1FFFFF).

**PowerShell Telemetry**: Only test framework boilerplate (Set-ExecutionPolicy commands and error handling scriptblocks) - no script block logging of the actual registry modification commands.

## What This Dataset Does Not Contain

**Sysmon Registry Events**: No Sysmon EID 13 (Registry value set) events are present, likely because the sysmon-modular configuration doesn't include registry monitoring for this specific Terminal Server path or registry monitoring may be disabled entirely.

**PowerShell Script Execution**: The actual registry modification commands aren't captured in PowerShell script block logging, suggesting they were executed through direct process invocation rather than PowerShell cmdlets.

**Network Activity**: No Sysmon network events showing actual RDP service changes or connection attempts following the configuration change.

**Service Modification**: No events showing Terminal Services/Remote Desktop Services being started or reconfigured after the registry change.

## Assessment

This dataset provides good coverage for process-based detection of registry modification attempts but lacks the actual registry modification telemetry that would be most valuable for this technique. The Security event log with command-line auditing provides the strongest detection signal, capturing the complete reg.exe command with the target registry path and value. Sysmon process creation events complement this with additional process metadata and parent-child relationships. However, the absence of Sysmon registry modification events (EID 13) significantly limits the dataset's utility for comprehensive registry monitoring strategies. This is a common limitation in environments where registry auditing isn't fully configured.

## Detection Opportunities Present in This Data

1. **Registry Modification Command Line Detection** - Security EID 4688 with command line `reg add "hklm\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp" /v SecurityLayer` targeting RDP security settings

2. **Suspicious Process Chain Analysis** - PowerShell spawning cmd.exe spawning reg.exe with registry modification parameters, detectable via Sysmon EID 1 ParentProcessGuid relationships

3. **Terminal Services Registry Path Targeting** - Command lines containing "Terminal Server\Winstations\RDP-Tcp" indicating RDP configuration changes

4. **SecurityLayer Value Manipulation** - Specific detection for registry commands modifying the SecurityLayer value to 0 (disabling Network Level Authentication)

5. **System-Level Registry Modification** - Detection of HKLM\SYSTEM registry modifications by non-administrative tools or unexpected processes

6. **Process Access Pattern Analysis** - Sysmon EID 10 showing PowerShell accessing cmd.exe with full privileges during registry modification operations

7. **Reconnaissance and Registry Modification Sequence** - Combined detection of whoami.exe execution followed by registry modification commands within the same process tree
