# T1112-48: Modify Registry — Event Viewer Registry Modification - Redirection URL

## Technique Context

T1112 (Modify Registry) involves attackers changing Windows Registry keys and values to establish persistence, escalate privileges, or evade defenses. This specific test modifies the Event Viewer's MicrosoftRedirectionURL registry value to point to an attacker-controlled resource. While this particular variant targets Event Viewer configuration, the broader technique encompasses registry modifications for DLL hijacking, service manipulation, startup persistence, and security control bypass. Detection teams focus on monitoring registry writes to sensitive keys, especially those involving system services, autorun locations, and security-related configurations. The registry serves as a critical persistence and evasion vector in Windows environments.

## What This Dataset Contains

This dataset captures a PowerShell-executed registry modification targeting Event Viewer configuration. The core malicious activity appears in Security event 4688, showing cmd.exe executing: `"cmd.exe" /c reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer" /v MicrosoftRedirectionURL /t REG_SZ /d "file://C:\windows\system32\notepad.exe" /f`. 

The process chain shows PowerShell (PID 32208) spawning cmd.exe (PID 12184), which then launches reg.exe (PID 1488) to perform the actual registry modification. Sysmon event 1 captures both cmd.exe and reg.exe process creations with the full command line, including the target registry key `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer` and the malicious redirection value `file://C:\windows\system32\notepad.exe`.

Sysmon events 10 show PowerShell accessing both spawned processes with full access rights (0x1FFFFF), indicating process monitoring behavior. The technique successfully completes with exit status 0x0 across all processes.

## What This Dataset Does Not Contain

The dataset lacks the actual registry modification event itself - no Sysmon event 13 (RegistryEvent) is present, indicating the sysmon-modular configuration doesn't monitor this specific registry key or the registry modification detection rules weren't triggered. Without registry monitoring events, the only evidence of the modification comes from process command lines rather than direct registry change telemetry.

The dataset also doesn't show any subsequent exploitation of the modified Event Viewer configuration, such as a user launching Event Viewer and triggering the malicious redirection URL. The PowerShell events contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual attack script content.

## Assessment

This dataset provides moderate detection value for T1112 through process-based monitoring. The Security 4688 events with command-line logging effectively capture the registry modification attempt via reg.exe, providing the target key, value name, and malicious data. Sysmon process creation events offer additional process relationship context and file hashes for behavioral analysis.

However, the lack of direct registry modification telemetry (Sysmon event 13) significantly limits visibility into the actual registry state changes. Detection engineers would need to rely on process command-line analysis rather than definitive registry monitoring, which could miss alternative modification methods (PowerShell Set-ItemProperty, direct API calls, etc.).

The dataset would be stronger with Sysmon registry monitoring configured for Event Viewer-related keys and other common persistence locations.

## Detection Opportunities Present in This Data

1. Monitor Security 4688 events for reg.exe command lines containing registry paths associated with system applications, particularly "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer"

2. Detect Sysmon event 1 process creations of reg.exe with "add" operations targeting HKLM software keys, especially those modifying URL or path configurations

3. Alert on command-line patterns containing "MicrosoftRedirectionURL" or similar redirection parameters in registry operations

4. Monitor process chains where PowerShell spawns cmd.exe, which then executes reg.exe for registry modifications

5. Detect file:// URI schemes in registry modification command lines, which could indicate malicious redirections

6. Flag reg.exe executions with the /f (force) parameter when targeting system application configuration keys

7. Correlate PowerShell process access events (Sysmon event 10) to spawned registry modification processes as potential automation indicators
