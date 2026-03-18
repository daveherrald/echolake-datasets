# T1112-70: Modify Registry — Enable RDP via Registry (fDenyTSConnections)

## Technique Context

T1112 Modify Registry is a fundamental technique used by adversaries to alter Windows registry settings for defense evasion and persistence purposes. This specific test (T1112-70) demonstrates enabling Remote Desktop Protocol (RDP) access by modifying the `fDenyTSConnections` registry value, a common administrative action that attackers leverage to establish remote access to compromised systems.

The `fDenyTSConnections` value in `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server` controls whether Terminal Services (RDP) connections are allowed. Setting this value to 0 enables RDP, while 1 disables it. This technique is particularly valuable to threat actors because RDP provides legitimate administrative access that can blend with normal IT operations, making detection challenging without proper context and baselining.

Detection engineers focus on monitoring registry modifications to security-relevant keys, especially those affecting remote access services, Windows Defender settings, authentication mechanisms, and startup persistence locations. The community emphasizes tracking both the technical indicators (registry paths, processes involved) and behavioral context (timing, user context, associated activities).

## What This Dataset Contains

The dataset captures a complete execution chain for enabling RDP via registry modification. The primary evidence appears in Sysmon EID 13 (Registry value set) showing the critical registry modification:

`TargetObject: HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections` with `Details: DWORD (0x00000000)` performed by `reg.exe` (PID 24144).

The process execution chain is clearly documented through Security 4688 events and Sysmon EID 1 events:
- PowerShell (PID 23080) spawns `cmd.exe /c reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f`
- cmd.exe (PID 23296) then spawns `reg.exe` with the actual registry modification command
- The reg.exe process (PID 24144) performs the registry write

Additional telemetry includes Sysmon EID 10 (Process Access) events showing PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF), and various DLL loading events (EID 7) as PowerShell initializes its .NET runtime environment.

Security event 4703 documents privilege escalation with multiple sensitive privileges being enabled including `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeLoadDriverPrivilege`.

## What This Dataset Does Not Contain

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual test execution commands. The Atomic Red Team test framework appears to execute the technique through a method that doesn't generate PowerShell script block logs for the core registry modification logic.

No Sysmon ProcessCreate events are captured for the initial PowerShell process due to the sysmon-modular configuration's include-mode filtering, which only captures processes matching known-suspicious patterns. The Security 4688 events provide this coverage instead.

There are no network connection events, file system changes beyond temporary PowerShell profile files, or Windows Defender alerts, indicating this registry modification executed successfully without triggering real-time protection mechanisms.

## Assessment

This dataset provides excellent telemetry for detecting registry-based RDP enabling techniques. The combination of Security 4688 command-line logging and Sysmon EID 13 registry monitoring creates robust detection opportunities. The complete process chain from PowerShell through cmd.exe to reg.exe is well-documented with full command lines preserved.

The registry modification itself is captured with precise details including the exact registry key, value name, data type, and new value. The process access events add additional behavioral context that could help distinguish malicious from administrative activity.

However, the dataset would be strengthened by PowerShell script block logging of the actual execution commands and potential network activity showing subsequent RDP usage of the newly enabled service.

## Detection Opportunities Present in This Data

1. **Registry Key Modification Detection** - Monitor Sysmon EID 13 for `TargetObject` containing `Terminal Server\fDenyTSConnections` with `Details` showing DWORD value 0x00000000

2. **Command-Line Pattern Matching** - Detect Security 4688 events with `Process Command Line` containing `reg add` combined with `Terminal Server` and `fDenyTSConnections` parameters

3. **Process Chain Analysis** - Identify PowerShell spawning cmd.exe which spawns reg.exe within short time windows, particularly when targeting Terminal Server registry keys

4. **Registry Tool Execution Context** - Monitor reg.exe executions (Sysmon EID 1) with `CommandLine` containing Terminal Server registry paths, especially when parent process is cmd.exe or PowerShell

5. **Process Access Behavioral Detection** - Correlate Sysmon EID 10 showing PowerShell accessing cmd.exe with full rights (0x1FFFFF) followed by registry modifications to RDP-related keys

6. **Privilege Escalation Correlation** - Combine Security 4703 privilege adjustment events showing sensitive privileges with subsequent registry modifications affecting remote access services
