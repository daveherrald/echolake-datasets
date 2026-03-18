# T1112-86: Modify Registry — Modify RDP-Tcp Initial Program Registry Entry

## Technique Context

T1112 (Modify Registry) is a fundamental defense evasion and persistence technique where attackers modify Windows registry keys to alter system behavior, disable security controls, or establish persistence mechanisms. This specific test (T1112-86) focuses on modifying RDP configuration settings in the registry, specifically the Terminal Server WinStations RDP-Tcp configuration.

The technique modifies two critical registry values under `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`: `fInheritInitialProgram` (enabled via DWORD value 1) and `InitialProgram` (set to execute notepad.exe). This configuration forces RDP sessions to automatically launch a specified program upon connection, which attackers can abuse to execute malicious payloads or establish persistence through legitimate remote access channels.

Detection engineers typically focus on monitoring registry modifications to security-relevant keys, particularly those affecting RDP configuration, startup programs, and security controls. This technique is especially concerning because it leverages legitimate RDP functionality for malicious purposes.

## What This Dataset Contains

The dataset captures the complete execution chain through multiple event sources. Security event 4688 shows the process creation sequence: PowerShell (PID 42708) spawning cmd.exe with the command line `"cmd.exe" /c reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v fInheritInitialProgram /t REG_DWORD /d 1 /f & reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v InitialProgram /t REG_SZ /d "C:\Windows\System32\notepad.exe" /f`.

Two separate reg.exe processes (PIDs 9740 and 40348) execute the registry modifications, with Sysmon EID 1 capturing both: `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v fInheritInitialProgram /t REG_DWORD /d 1 /f` and `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v InitialProgram /t REG_SZ /d "C:\Windows\System32\notepad.exe" /f`.

The critical registry modification is captured in Sysmon EID 13: `HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\InitialProgram` set to `C:\Windows\System32\notepad.exe`. Additional Sysmon events include process access events (EID 10) showing PowerShell accessing child processes and various image load events (EID 7) during PowerShell execution.

## What This Dataset Does Not Contain

The dataset only captures one of the two registry modifications in Sysmon EID 13 events. While we see the `InitialProgram` value being set, there's no corresponding Sysmon EID 13 for the `fInheritInitialProgram` DWORD modification, likely due to Sysmon configuration filtering. This is significant because both registry changes are necessary for the attack to function properly.

PowerShell telemetry consists entirely of test framework boilerplate (Set-StrictMode and Set-ExecutionPolicy commands), providing no insight into the actual technique execution. The missing registry event limits visibility into the complete attack sequence, though the Security 4688 events with command-line logging provide the full command context.

## Assessment

This dataset provides good visibility into T1112 registry modification techniques through multiple complementary event sources. The combination of Security 4688 command-line logging and Sysmon EID 1 process creation events delivers complete process genealogy and command-line details. Sysmon EID 13 captures the critical registry modification, though with incomplete coverage.

The data quality is strong for building detections focused on RDP configuration tampering, particularly through the distinctive registry path and the use of reg.exe for modifications. However, the incomplete Sysmon registry coverage represents a detection gap that organizations should be aware of when tuning their Sysmon configurations for comprehensive registry monitoring.

## Detection Opportunities Present in This Data

1. **Registry Path Targeting**: Monitor Sysmon EID 13 for modifications to `HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\InitialProgram` and related RDP configuration keys.

2. **Command Line Pattern Detection**: Alert on Security EID 4688 or Sysmon EID 1 events containing reg.exe with command lines targeting Terminal Server registry paths, particularly with `/v InitialProgram` or `/v fInheritInitialProgram` parameters.

3. **Process Chain Analysis**: Detect PowerShell spawning cmd.exe which subsequently launches reg.exe targeting RDP registry configuration paths.

4. **RDP Configuration Tampering**: Build signatures for any registry modifications under `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server` that alter default RDP behavior.

5. **Batch Command Monitoring**: Monitor for cmd.exe processes executing compound commands (using `&` operator) that modify multiple registry keys in sequence, particularly RDP-related configurations.

6. **Administrative Tool Abuse**: Track reg.exe executions with elevated privileges targeting security-relevant registry hives, especially when spawned from scripting engines like PowerShell.
