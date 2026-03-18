# T1112-40: Modify Registry — NetWire RAT Registry Key Creation

## Technique Context

T1112 (Modify Registry) is a fundamental technique used by adversaries for both defense evasion and persistence on Windows systems. Attackers modify registry keys and values to achieve various objectives: establishing persistence mechanisms, disabling security controls, storing configuration data, or hiding malicious activities. The NetWire RAT, a commercial remote access tool frequently abused by threat actors, exemplifies this technique by creating specific registry entries to maintain persistence and store operational configuration data.

The detection community focuses heavily on monitoring registry modifications, particularly those targeting well-known persistence locations like Run keys, security-related settings, and unusual application-specific registry paths. NetWire's registry footprint is particularly interesting because it creates both persistence entries and configuration storage, making it a valuable case study for detection engineering.

## What This Dataset Contains

This dataset captures a complete NetWire RAT registry key creation simulation executed through PowerShell and cmd.exe. The core activity consists of three sequential reg.exe executions:

Security event 4688 shows the initial command execution: `"cmd.exe" /c reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v NetWire /t REG_SZ /d "C:\Users\admin\AppData\Roaming\Install\Host.exe" /f & reg add HKCU\SOFTWARE\NetWire /v HostId /t REG_SZ /d HostId-kai6Ci /f & reg add HKCU\SOFTWARE\NetWire /v "Install Date" /t REG_SZ /d "2021-08-30 07:17:27" /f`

The dataset includes complete process creation telemetry from both Security 4688 events and Sysmon EID 1, showing:
- PowerShell process (PID 18672) spawning cmd.exe (PID 11300)
- Three reg.exe processes creating the NetWire registry structure
- Process termination events for all spawned processes

Most critically, Sysmon EID 13 captures the actual registry modification: `Registry value set: TargetObject: HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run\NetWire` with `Details: C:\Users\admin\AppData\Roaming\Install\Host.exe`

The process chain shows typical PowerShell-based execution: powershell.exe → cmd.exe → reg.exe, with full command-line visibility and process access events (Sysmon EID 10) showing PowerShell accessing the spawned processes.

## What This Dataset Does Not Contain

The dataset is missing registry creation events for the NetWire-specific configuration keys. While Sysmon EID 13 captured the Run key creation (the persistence mechanism), it did not capture the creation of `HKCU\SOFTWARE\NetWire\HostId` or `HKCU\SOFTWARE\NetWire\Install Date` registry values. This gap likely results from the sysmon-modular configuration's registry monitoring rules, which may prioritize well-known persistence locations over custom application registry paths.

The PowerShell events contain only execution policy changes and boilerplate script blocks, with no evidence of the actual registry modification commands being logged at the PowerShell script block level. This suggests the technique was executed through direct process spawning rather than PowerShell registry cmdlets.

There are no Windows Defender detection events despite the creation of a clear persistence mechanism, indicating the technique successfully evaded real-time protection scanning.

## Assessment

This dataset provides excellent telemetry for detecting NetWire RAT registry modifications and similar persistence techniques. The combination of Security 4688 process creation events with full command-line logging, Sysmon EID 1 process creation, and Sysmon EID 13 registry modifications creates multiple detection opportunities at different telemetry layers.

The process execution chain is completely visible, and the registry modification targeting the Run key persistence location is captured with full context including the malicious executable path. The command-line arguments clearly show NetWire-specific artifacts (application name, host ID format, install date) that enable both signature-based and behavioral detection approaches.

The missing NetWire configuration registry events represent a minor gap, but the captured Run key creation is the most security-relevant modification from a persistence detection perspective.

## Detection Opportunities Present in This Data

1. **NetWire Run Key Creation** - Sysmon EID 13 shows registry value creation at `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\NetWire` with suspicious executable path, enabling detection of NetWire persistence establishment

2. **Command-line NetWire Indicators** - Security 4688 and Sysmon EID 1 capture reg.exe command lines containing NetWire-specific strings ("NetWire", "HostId-", "Install Date") and suspicious AppData\Roaming\Install paths

3. **Bulk Registry Modification Pattern** - Sequential reg.exe process creation events within seconds, all modifying NetWire-related registry locations, indicates automated malware installation behavior

4. **PowerShell-to-CMD-to-Reg Process Chain** - The execution chain powershell.exe → cmd.exe → multiple reg.exe processes represents a common malware deployment pattern detectable through process ancestry analysis

5. **Suspicious Executable Path Pattern** - The target executable path `C:\Users\admin\AppData\Roaming\Install\Host.exe` follows typical malware naming conventions (generic folder/filename) in user profile directories

6. **Registry Persistence Technique Detection** - Standard T1547.001 detection targeting any creation of Run key values with executable paths in user-writable directories

7. **NetWire HostId Format Recognition** - The "HostId-kai6Ci" string format matches known NetWire configuration patterns, enabling threat intelligence-based detection
