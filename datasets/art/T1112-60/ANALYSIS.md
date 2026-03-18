# T1112-60: Modify Registry — Modify Internet Zone Protocol Defaults in Current User Registry - PowerShell

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries modify Windows registry keys to disable security protections, establish persistence, or alter system behavior. This specific test targets Internet Explorer's zone mapping protocol defaults, which control how IE and applications using the WebBrowser control handle different protocols (http/https) and assign them to security zones.

The technique modifies `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults` to set both `http` and `https` values to `0` (Local Machine zone). This effectively treats all web content as trusted local content, bypassing security restrictions normally applied to internet content. Attackers use this technique to weaken browser security for privilege escalation, credential harvesting, or enabling execution of malicious web content.

Detection engineers focus on monitoring registry modifications to security-sensitive keys, particularly those affecting browser security zones, execution policies, and trust relationships.

## What This Dataset Contains

This dataset captures a successful PowerShell-based registry modification attack with complete telemetry across multiple channels:

**Security Channel (10 events):** Process creation and termination events showing the attack chain:
- EID 4688: PowerShell process created with command line `"powershell.exe" & {# Set the registry values for http and https to 0\nSet-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults' -Name 'http' -Value 0\nSet-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults' -Name 'https' -Value 0}`
- Multiple 4689 process termination events for PowerShell and associated processes

**PowerShell Channel (31 events):** Script block logging capturing the exact registry modifications:
- EID 4104: Script block containing the actual technique: `Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults' -Name 'http' -Value 0` and the https equivalent
- EID 4103: Command invocation events for both `Set-ItemProperty` operations with parameter binding showing Path, Name, and Value parameters

**Sysmon Channel (26 events):** Process creation and system activity:
- EID 1: PowerShell process creation with full command line showing the registry modification script
- EID 1: whoami.exe execution for system discovery
- Multiple EID 7: Image load events for .NET runtime components and Windows Defender modules
- EID 10: Process access events between PowerShell processes
- EID 11: File creation events for PowerShell profile data
- EID 17: Named pipe creation for PowerShell host communication

## What This Dataset Does Not Contain

**Registry Modification Events:** Critically, this dataset lacks Sysmon EID 12/13/14 registry events that would directly capture the registry value modifications. The sysmon-modular configuration appears to have filtered out registry monitoring, which means we cannot see the actual `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults` key modifications that constitute the core of this technique.

**Object Access Auditing:** No Security 4663 events showing registry key access, as object access auditing was disabled (`object_access: none` in the audit policy).

**Registry Persistence Artifacts:** No evidence of whether the modifications actually persisted or were successfully applied to the target registry hive.

## Assessment

This dataset provides **moderate value** for detection engineering despite missing the core registry events. The PowerShell script block logging (EID 4104/4103) provides complete visibility into the attack commands and parameters, making it excellent for content-based detection. The Security 4688 events with command-line logging offer an additional detection layer.

However, the absence of registry modification events significantly limits the dataset's utility for comprehensive T1112 detection development. Ideally, Sysmon registry monitoring (EID 12/13/14) would be enabled to capture the actual registry changes, providing definitive proof of technique success and enabling registry-focused detections.

The dataset is most valuable for PowerShell-based detection development and demonstrates how script block logging can compensate for missing system-level events in some scenarios.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Analysis** - Monitor EID 4104 for script blocks containing `Set-ItemProperty` operations targeting `Internet Settings\ZoneMap\ProtocolDefaults` registry paths

2. **PowerShell Command Invocation Monitoring** - Detect EID 4103 events showing `Set-ItemProperty` cmdlet usage with parameters targeting browser security registry keys

3. **Process Command Line Detection** - Alert on Security 4688 or Sysmon EID 1 events with command lines containing registry modification commands targeting Internet zone protocol defaults

4. **Suspicious PowerShell Parameter Combinations** - Monitor for PowerShell cmdlets modifying registry paths containing `ZoneMap\ProtocolDefaults` with value `0` (Local Machine zone)

5. **Browser Security Registry Path Targeting** - Detect any registry operations (when available) targeting `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap` subkeys

6. **PowerShell Process Chain Analysis** - Correlate PowerShell parent-child process relationships where child processes execute registry modification commands

7. **Zone Mapping Value Changes** - Monitor for registry value changes setting protocol defaults to zone `0`, indicating potential security zone bypass attempts
