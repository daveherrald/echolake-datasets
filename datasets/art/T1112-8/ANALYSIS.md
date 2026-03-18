# T1112-8: Modify Registry — BlackByte Ransomware Registry Changes - CMD

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries modify Windows registry values to evade security controls, maintain persistence, or facilitate other malicious activities. The BlackByte ransomware family, like many modern ransomware variants, makes specific registry modifications to optimize its operational environment. These changes typically focus on disabling security features, enabling network connectivity for lateral movement, and configuring system settings to support file system operations.

This particular test simulates BlackByte's registry modification behavior using command-line tools (`cmd.exe` and `reg.exe`), making three specific changes: setting `LocalAccountTokenFilterPolicy` and `EnableLinkedConnections` in the UAC policy hive to facilitate privilege escalation and network access, and enabling `LongPathsEnabled` in the file system control settings to support operations on files with extended path names. Detection engineers focus on monitoring registry modifications to these specific keys, unusual command-line patterns involving `reg.exe`, and process chains that indicate systematic registry tampering.

## What This Dataset Contains

The dataset captures the complete execution chain of BlackByte's registry modification technique through multiple data sources. Security event 4688 shows the primary command execution: `"cmd.exe" /c cmd.exe /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f & cmd.exe /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLinkedConnections /t REG_DWORD /d 1 /f & cmd.exe /c reg add HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1 /f`. 

Sysmon provides detailed process creation events (EID 1) for the entire execution chain: PowerShell spawns the initial cmd.exe, which then spawns three child cmd.exe processes, each executing a reg.exe process with specific registry modification commands. The most critical telemetry comes from Sysmon EID 13 (Registry value set) events, which capture the actual registry modifications: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` set to `DWORD (0x00000001)` and `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLinkedConnections` set to `DWORD (0x00000001)`.

Process access events (Sysmon EID 10) show PowerShell accessing the spawned processes with full access rights (`GrantedAccess: 0x1FFFFF`), indicating process monitoring behavior. All processes execute with SYSTEM privileges and exit cleanly (Security EID 4689 with `Exit Status: 0x0`).

## What This Dataset Does Not Contain

Notably absent is a Sysmon EID 13 event for the third registry modification (`HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled`). While Security events show the `reg.exe` process executing with the correct command line, the corresponding registry modification telemetry is missing. This could indicate the value was already set, the modification failed, or there's a gap in the Sysmon configuration for this particular registry key.

The dataset lacks any Windows Defender blocking or alerting events, suggesting these registry modifications were not flagged as malicious by the endpoint protection system. There are no application log events documenting the registry changes from a system perspective, which would normally complement Sysmon's process-focused telemetry.

## Assessment

This dataset provides excellent coverage of the process execution aspects of T1112 but has a critical gap in registry modification telemetry for one of the three targeted keys. The Security channel's command-line logging provides robust evidence of the attempted registry modifications, while Sysmon's process creation and registry value set events offer detailed technical context for two of the three operations.

For detection engineering purposes, the data is strong for building process-based detections around suspicious `reg.exe` usage patterns and command-line analysis. However, the missing registry modification event for `LongPathsEnabled` highlights the importance of having multiple detection approaches, as relying solely on Sysmon EID 13 would miss some registry changes.

## Detection Opportunities Present in This Data

1. **Registry modification to UAC policy keys** - Monitor Sysmon EID 13 for changes to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` and `EnableLinkedConnections` with DWORD value 1, especially when performed by `reg.exe`

2. **BlackByte-specific command pattern** - Detect Security EID 4688 command lines containing multiple chained `reg add` commands targeting the specific registry paths used by BlackByte ransomware

3. **Bulk registry modification behavior** - Identify processes executing multiple `reg.exe` child processes in rapid succession (within seconds) targeting different HKLM policy and system keys

4. **Privilege escalation preparation** - Alert on modifications to `LocalAccountTokenFilterPolicy` and `EnableLinkedConnections` registry values, as these are commonly used to facilitate UAC bypass and lateral movement

5. **Process chain analysis** - Monitor for PowerShell or cmd.exe spawning multiple cmd.exe children that each execute reg.exe with `HKLM` modifications, indicating systematic registry tampering

6. **Registry tool abuse** - Detect reg.exe processes with command lines containing `/f` (force) flag combined with DWORD value modifications to security-relevant registry paths
