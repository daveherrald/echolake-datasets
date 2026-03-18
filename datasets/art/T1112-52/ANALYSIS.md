# T1112-52: Modify Registry — Disable Windows OS Auto Update

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries alter Windows registry entries to change system behavior, disable security features, or maintain persistence. This specific test (T1112-52) targets Windows Update functionality by setting the `NoAutoUpdate` registry value to disable automatic updates—a common technique used by malware and ransomware to prevent security patches from being applied.

The detection community focuses on registry modifications to critical system areas, particularly those affecting security controls like Windows Update, Windows Defender, UAC, and authentication mechanisms. Registry changes to `HKLM\SOFTWARE\Policies` are especially significant as they typically require elevated privileges and affect system-wide behavior. The combination of command-line tools (reg.exe) and specific registry paths creates high-fidelity detection opportunities.

## What This Dataset Contains

This dataset captures a successful registry modification sequence executed by PowerShell launching reg.exe through cmd.exe. The key telemetry includes:

**Process Chain Evidence (Security 4688):**
- PowerShell spawning cmd.exe: `"cmd.exe" /c reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f`
- cmd.exe spawning reg.exe: `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f`

**Sysmon Process Creation (EID 1):**
- whoami.exe execution for discovery: `"C:\Windows\system32\whoami.exe"`
- cmd.exe with full registry modification command line
- reg.exe with the actual registry add operation

**Process Termination Evidence (Security 4689):**
- All processes (reg.exe, cmd.exe, PowerShell) exited with status 0x0, indicating successful execution

**Process Access (Sysmon EID 10):**
- PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF)

**Additional Context:**
- System 7040 shows Background Intelligent Transfer Service changed from auto to demand start
- Multiple PowerShell script blocks containing only test framework boilerplate
- Various .NET and Windows Defender DLL loads during PowerShell execution

## What This Dataset Does Not Contain

The dataset lacks direct registry modification telemetry—there are no Sysmon EID 13 (Registry value set) events despite the successful execution. This is likely due to the sysmon-modular configuration filtering certain registry events or the specific registry path not being monitored. Additionally, there are no Windows Defender detection events despite real-time protection being enabled, suggesting this technique successfully bypassed endpoint protection.

The dataset also doesn't contain any WMI events related to the actual registry modification, only a generic WMI activity event. File system events (Sysmon EID 11) only show PowerShell profile file creation, not any registry-related file operations.

## Assessment

This dataset provides excellent process execution telemetry for detecting registry-based defense evasion. The Security event log with command-line auditing captures the complete attack chain with full command-line arguments, making it highly valuable for detection engineering. The combination of Security 4688 events and Sysmon EID 1 events provides redundant coverage of the critical process executions.

However, the absence of registry modification telemetry (Sysmon EID 13) significantly limits the dataset's utility for detecting the actual registry changes versus just the process execution. This gap means defenders would need to rely on process-based detections rather than registry-based ones, which may produce more false positives.

## Detection Opportunities Present in This Data

1. **Registry tool execution with Windows Update paths** - Monitor reg.exe command lines containing "WindowsUpdate" or "NoAutoUpdate" registry paths

2. **PowerShell spawning registry modification tools** - Detect powershell.exe parent processes launching cmd.exe with reg.exe commands 

3. **Specific registry modification commands** - Alert on reg.exe with "add" operations targeting HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU

4. **Defense evasion via Windows Update disable** - Monitor for the specific command pattern `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f`

5. **Process chain analysis** - Correlate PowerShell → cmd.exe → reg.exe process lineage with registry-related command lines

6. **Privilege escalation context** - Monitor registry modifications to HKLM\SOFTWARE\Policies by SYSTEM context processes spawned from user sessions

7. **Service configuration changes** - Alert on System EID 7040 events showing Background Intelligent Transfer Service being disabled alongside registry modifications
