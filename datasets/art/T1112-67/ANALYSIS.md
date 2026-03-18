# T1112-67: Modify Registry — Enable Proxy Settings

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries modify Windows registry keys to evade detection, maintain persistence, or alter system behavior. Proxy configuration manipulation is particularly interesting because it can enable network traffic redirection for C2 communications, data exfiltration, or bypassing security controls. Attackers often target the `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` registry path to enable proxy settings (ProxyEnable=1) and potentially set proxy servers for network traffic routing.

The detection community focuses on monitoring registry modifications to sensitive keys, especially those related to network configuration, security settings, and persistence mechanisms. This specific test demonstrates a common post-exploitation activity where attackers configure system proxy settings to route traffic through attacker-controlled infrastructure.

## What This Dataset Contains

This dataset captures a straightforward registry modification attack using the built-in `reg.exe` utility. The attack flow is:

1. **PowerShell Execution**: A PowerShell process (PID 36668) spawns and executes the proxy configuration command
2. **Command Shell Invocation**: PowerShell spawns cmd.exe with the command `"cmd.exe" /c reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f`
3. **Registry Modification**: cmd.exe spawns reg.exe with the actual registry modification command: `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f`

The Security channel captures the complete process creation chain in events 4688, showing the command lines clearly. Sysmon events 1 capture the process creations for cmd.exe and reg.exe (the sysmon-modular config's include-mode filtering captured these LOLBins). Notably, Sysmon events 10 show PowerShell accessing both child processes with full access rights (0x1FFFFF), indicating process monitoring behavior.

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no actual attack script content captured.

## What This Dataset Does Not Contain

Critically, this dataset lacks **Sysmon Event ID 13 (Registry Value Set)** events that would directly show the registry modification taking place. This is likely because the sysmon-modular configuration doesn't monitor the specific Internet Settings registry path being modified. Without these events, we cannot confirm the registry change actually occurred or see the specific values being set.

The dataset also doesn't contain any network activity that might result from the proxy configuration, though this test appears to only enable the proxy setting without specifying an actual proxy server.

There are no Windows Defender alerts or blocks, suggesting this basic registry modification technique executed successfully without triggering behavioral detection.

## Assessment

This dataset provides good visibility into the process execution chain for registry-based proxy manipulation but lacks the most critical evidence—the actual registry modifications themselves. The Security 4688 events with command-line logging provide excellent process-based detection opportunities, and Sysmon process creation events add valuable context. However, without Sysmon registry monitoring configured for Internet Settings, the core technique evidence is missing.

For detection engineering focused on process-based indicators, this dataset is quite useful. For registry-focused detection rules, it demonstrates the gap that occurs when registry monitoring isn't properly configured for attack-relevant paths.

## Detection Opportunities Present in This Data

1. **Command-line detection of reg.exe proxy modification**: Security 4688 events capture the exact command `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f`

2. **Process chain analysis**: PowerShell -> cmd.exe -> reg.exe execution pattern with proxy-related command arguments

3. **Sysmon process creation for reg.exe with Internet Settings arguments**: Event ID 1 showing reg.exe with command line targeting proxy settings

4. **PowerShell process access to child processes**: Sysmon Event ID 10 showing PowerShell accessing spawned cmd.exe and whoami.exe processes with full rights

5. **LOLBin execution pattern**: cmd.exe and reg.exe spawned from PowerShell for system configuration changes

6. **Registry modification tool invocation**: Any execution of reg.exe with "Internet Settings" path arguments, regardless of specific values being set
