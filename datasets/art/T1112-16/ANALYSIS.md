# T1112-16: Modify Registry — Disable Windows Change Password Feature

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries modify the Windows Registry to evade defenses, establish persistence, or alter system behavior. This specific test targets the DisableChangePassword policy, which prevents users from changing their passwords through normal Windows interfaces. Attackers often disable security-related policies to maintain access or prevent users from rotating credentials. The detection community focuses on monitoring registry modifications to security-critical keys, especially those under HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System, as these directly impact security controls and user privileges.

## What This Dataset Contains

This dataset captures a successful registry modification using the native `reg.exe` utility. The attack chain shows:

1. **PowerShell execution**: Security event 4688 shows PowerShell spawning cmd.exe with command line `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableChangePassword /t REG_DWORD /d 1 /f`

2. **Registry tool execution**: Security event 4688 captures reg.exe with the complete command line `reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableChangePassword /t REG_DWORD /d 1 /f`

3. **Registry modification**: Sysmon EID 13 shows the actual registry write: `HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\policies\system\DisableChangePassword` set to `DWORD (0x00000001)`

4. **Process creation telemetry**: Sysmon EID 1 events capture both the cmd.exe and reg.exe process creations with full command lines and process relationships

5. **Process access**: Sysmon EID 10 events show PowerShell accessing the spawned processes

The PowerShell channel contains only test framework boilerplate (Set-ExecutionPolicy calls and error handling scriptblocks), providing no technique-specific content.

## What This Dataset Does Not Contain

The dataset lacks several elements that could enhance detection coverage:

- **Direct PowerShell registry modification**: The technique uses cmd.exe and reg.exe rather than PowerShell cmdlets like Set-ItemProperty, missing direct PowerShell-based registry telemetry
- **Registry access events**: Windows Security audit policy doesn't include object access auditing, so there are no 4656/4663 events showing registry key access
- **User context clarity**: The technique runs as NT AUTHORITY\SYSTEM, but targets HKEY_CURRENT_USER, which resolves to HKU\.DEFAULT in this context
- **Process termination timing**: While Security 4689 events show process exits, there's no clear indication of whether the registry change was successfully applied before cleanup

## Assessment

This dataset provides excellent coverage for detecting registry-based policy manipulation through native Windows tools. The Security 4688 events with command-line logging offer immediate detection opportunities, while Sysmon EID 13 provides definitive evidence of the registry modification. The combination of process creation, command-line capture, and registry value changes creates multiple detection layers. However, the technique's reliance on legitimate system tools (cmd.exe, reg.exe) means detections must focus on the specific registry keys and values being modified rather than the tools themselves. The dataset is strong for building detections around policy tampering but would benefit from similar tests using PowerShell cmdlets or direct API calls for comprehensive coverage.

## Detection Opportunities Present in This Data

1. **Registry policy tampering detection**: Sysmon EID 13 events targeting `*\policies\system\DisableChangePassword` with value `0x00000001` indicate password change prevention

2. **Command-line pattern matching**: Security 4688 events with command lines containing `reg add` operations against `*Policies\System*` keys with security-relevant values

3. **Process chain analysis**: PowerShell spawning cmd.exe which spawns reg.exe with registry modification parameters indicates potential policy tampering

4. **Security policy modification monitoring**: Registry writes to `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\*` or `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\*` keys

5. **Credential-related policy detection**: Specific monitoring for DisableChangePassword, DisableLockWorkstation, and other credential management policy modifications

6. **Native tool abuse detection**: reg.exe execution with parameters targeting user policy hives (`HKEY_CURRENT_USER` or `HKU\*`) for security-sensitive values
