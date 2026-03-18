# T1112-64: Modify Registry — Disable Remote Desktop Anti-Alias Setting Through Registry

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where attackers manipulate Windows registry keys to alter system behavior, disable security features, or maintain persistence. This specific test (T1112-64) targets Remote Desktop Services configuration by disabling the anti-aliasing feature through registry modification. While seemingly benign, this demonstrates how attackers can manipulate RDP settings to potentially improve performance for their remote access sessions or disable features that might interfere with their tools. The detection community focuses on monitoring registry modifications to sensitive paths, particularly those affecting security controls, system services, and remote access configurations.

## What This Dataset Contains

This dataset captures a successful registry modification attack executed through PowerShell and cmd.exe. The core evidence appears in Security event 4688 showing the command line: `"cmd.exe" /c reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisableRemoteDesktopAntiAlias" /t REG_DWORD /d 1 /f`. 

The attack follows a clear process chain: PowerShell (PID 8332) spawns cmd.exe (PID 9716), which then executes reg.exe (PID 14684) to perform the actual registry modification. Sysmon provides comprehensive process creation telemetry with EID 1 events capturing this full execution chain. The reg.exe process shows the complete command line targeting `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services` with the specific value `DisableRemoteDesktopAntiAlias` set to 1.

Process access events (Sysmon EID 10) show PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF), indicating the elevated privileges required for this operation. All processes run under NT AUTHORITY\SYSTEM context with TokenElevationTypeDefault, confirming system-level access.

## What This Dataset Does Not Contain

Notably absent are registry modification events (Sysmon EID 13) that would directly show the registry value being written. The sysmon-modular configuration likely filters out this specific registry path as it's not considered high-priority for detection. There are no Windows Defender alerts or blocking events, indicating this registry modification was permitted by the endpoint protection system. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without the actual technique execution commands, suggesting the malicious PowerShell content was executed through other means or filtered from logging.

## Assessment

This dataset provides excellent process execution telemetry for detecting this registry modification technique. The Security channel's command-line auditing captures the complete attack vector with full command-line arguments, making it highly valuable for detection engineering. The Sysmon process creation events complement this with additional context including file hashes, parent-child relationships, and process access patterns. However, the absence of direct registry modification events limits the ability to build detections focused on the actual registry changes rather than the processes used to create them. This is still a strong dataset for behavioral detection but lacks the registry-level indicators that would make it comprehensive.

## Detection Opportunities Present in This Data

1. **Registry modification via reg.exe command line** - Monitor Security EID 4688 for reg.exe executions with "add" operations targeting Terminal Services registry paths, specifically commands containing "DisableRemoteDesktopAntiAlias"

2. **Suspicious PowerShell-to-cmd process chain** - Alert on Sysmon EID 1 process creation events showing PowerShell spawning cmd.exe with registry modification commands in the command line

3. **High-privilege process access patterns** - Monitor Sysmon EID 10 for PowerShell processes accessing system utilities like cmd.exe and reg.exe with full access rights (0x1FFFFF)

4. **Terminal Services policy modifications** - Create detection rules for any registry operations targeting the "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" key path through command-line tools

5. **reg.exe execution with force flag** - Monitor for reg.exe processes launched with the "/f" (force) parameter, particularly when combined with Terminal Services registry paths, as this bypasses confirmation prompts typical of legitimate administrative changes
