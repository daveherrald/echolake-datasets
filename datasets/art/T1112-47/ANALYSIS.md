# T1112-47: Modify Registry — Mimic Ransomware - Allow Multiple RDP Sessions per User

## Technique Context

T1112 Modify Registry is a fundamental technique where adversaries alter Windows registry entries to achieve persistence, defense evasion, or system configuration changes. This specific test mimics a common ransomware behavior: modifying the `fSingleSessionPerUser` registry value to allow multiple RDP sessions per user account. Ransomware operators often make this change to maintain persistent remote access even after legitimate users are logged in, facilitating continued access for data exfiltration or lateral movement. Detection engineers focus on registry modifications to sensitive Terminal Services keys, especially those that alter security boundaries or enable unauthorized access capabilities.

## What This Dataset Contains

This dataset captures a complete registry modification sequence executed via PowerShell and reg.exe. The attack chain begins with PowerShell (PID 30640) spawning `whoami.exe` for reconnaissance, then executing `cmd.exe /c reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fSingleSessionPerUser /t REG_DWORD /d 0 /f`. The critical registry modification is captured in Sysmon EID 13: `HKLM\System\CurrentControlSet\Control\Terminal Server\fSingleSessionPerUser` set to `DWORD (0x00000000)`, performed by reg.exe (PID 12584).

Security event 4688 shows the complete command line: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fSingleSessionPerUser /t REG_DWORD /d 0 /f`. The process chain is clearly documented: powershell.exe → cmd.exe → reg.exe, with all processes running as NT AUTHORITY\SYSTEM. Sysmon events 1, 10, and 13 provide comprehensive coverage of process creation, access patterns, and the actual registry modification.

## What This Dataset Does Not Contain

The dataset lacks any blocking or mitigation telemetry from Windows Defender—all processes completed successfully with exit status 0x0. There are no Sysmon EID 12 (Registry Object Added/Deleted) events, suggesting the registry key already existed and only the value was modified. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual PowerShell commands that triggered the registry change. File system monitoring shows only PowerShell profile creation, not any dropped files or additional persistence mechanisms.

## Assessment

This dataset provides excellent coverage for detecting registry-based persistence techniques targeting Terminal Services. The combination of Security 4688 events with full command-line logging and Sysmon EID 13 registry monitoring creates multiple detection opportunities. The clear process ancestry from PowerShell to reg.exe, combined with the specific registry modification, makes this an ideal dataset for building detections around ransomware-style RDP configuration changes. The lack of evasion attempts or obfuscation makes the technique signatures very clear and actionable.

## Detection Opportunities Present in This Data

1. Monitor Sysmon EID 13 registry modifications to `HKLM\System\CurrentControlSet\Control\Terminal Server\fSingleSessionPerUser` where the value is set to 0
2. Detect Security EID 4688 process creation events with command lines containing `reg add` operations targeting Terminal Server registry keys
3. Alert on process chains where PowerShell spawns cmd.exe which then executes reg.exe with Terminal Services-related arguments
4. Monitor registry modifications that disable single-session restrictions (`fSingleSessionPerUser = 0`) as potential ransomware behavior
5. Correlate Sysmon EID 1 process creation events for reg.exe with command lines modifying RDP configuration settings
6. Track privileged (SYSTEM context) registry modifications to Terminal Services configuration that could enable unauthorized remote access
