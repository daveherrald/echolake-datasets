# T1112-74: Modify Registry — Disable Windows Remote Desktop Protocol

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries alter Windows registry keys to disable security controls, maintain persistence, or evade detection. The specific test executed here disables Windows Remote Desktop Protocol (RDP) by setting the `fDenyTSConnections` registry value to 1, preventing remote desktop access to the system. This technique is commonly used by ransomware groups and other malicious actors to prevent administrators from remotely accessing compromised systems during an attack. Detection engineers focus on monitoring registry modifications to critical system settings, particularly those affecting remote access capabilities, security controls, and system configuration.

## What This Dataset Contains

This dataset captures a successful registry modification executed through PowerShell and cmd.exe. The attack chain shows PowerShell (PID 13828) spawning cmd.exe with the command line `"cmd.exe" /c reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f`, followed by cmd.exe spawning reg.exe (PID 24768) with the command `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f`. The critical registry modification is captured in Sysmon EID 13: `TargetObject: HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections` with `Details: DWORD (0x00000001)`. Security events show the complete process chain with EID 4688 events documenting process creation with full command lines. PowerShell events contain only test framework boilerplate (Set-ExecutionPolicy, Set-StrictMode) without the actual malicious commands.

## What This Dataset Does Not Contain

The dataset does not capture any attempts by Windows Defender to block this technique, as registry modifications through legitimate Windows utilities like reg.exe typically pass through security controls. There are no Sysmon ProcessCreate (EID 1) events for the initial PowerShell processes due to the sysmon-modular configuration using include-mode filtering that doesn't trigger on standard powershell.exe execution. The PowerShell script block logging (EID 4104) doesn't contain the actual registry modification commands, only capturing PowerShell engine initialization artifacts. No network activity, file system changes beyond PowerShell profile updates, or additional persistence mechanisms are present in this focused registry modification test.

## Assessment

This dataset provides excellent telemetry for detecting registry-based RDP disabling techniques. The combination of Security EID 4688 events with command-line logging and Sysmon EID 13 registry modification events creates a comprehensive detection opportunity. The process chain from PowerShell → cmd.exe → reg.exe with the specific registry target and value is clearly visible and actionable. The registry modification event contains all necessary details for building precise detections without false positives. This represents a high-fidelity detection scenario where the technique generates clear, unambiguous telemetry across multiple log sources.

## Detection Opportunities Present in This Data

1. Monitor Sysmon EID 13 registry modifications to `HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections` where the value is set to 1 (DWORD 0x00000001)

2. Detect Security EID 4688 process creation events for reg.exe with command lines containing "Terminal Server" and "fDenyTSConnections" parameters

3. Correlate PowerShell process spawning cmd.exe followed by reg.exe execution within a short timeframe, particularly when targeting RDP-related registry keys

4. Alert on any process modifying the `fDenyTSConnections` registry value, regardless of the parent process chain

5. Monitor for reg.exe executions with the specific pattern: `/v fDenyTSConnections /t REG_DWORD /d 1` indicating RDP disabling intent

6. Create behavioral detection for legitimate administrative tools (cmd.exe, reg.exe) being used to disable remote access services when executed by unexpected parent processes
