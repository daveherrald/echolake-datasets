# T1112-90: Modify Registry — Adding custom paths for application execution

## Technique Context

T1112 Modify Registry is a defense evasion and persistence technique where attackers modify the Windows registry to alter system behavior, disable security controls, or establish persistence. This specific test (T1112-90) focuses on hijacking application execution paths by modifying the `App Paths` registry key, which Windows uses to locate executables when they're invoked without a full path.

The technique targets `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\`, where each subkey represents an application name and its default value points to the executable's location. By modifying an existing application's path (in this case, `msedge.exe`), attackers can redirect execution to malicious binaries while maintaining the appearance of legitimate application launches.

Detection engineers typically focus on monitoring registry modifications to sensitive paths, especially those involving execution redirection, security settings, or autostart mechanisms. The App Paths technique is particularly insidious because it leverages legitimate Windows functionality to achieve code execution.

## What This Dataset Contains

The dataset captures a successful registry modification attack through PowerShell executing a command shell and reg.exe. The process chain shows:

1. **PowerShell execution**: Sysmon EID 1 captures the initial PowerShell process (PID 13984) with command line `powershell.exe`
2. **Command shell spawn**: Sysmon EID 1 shows cmd.exe (PID 14200) launched with the full attack command: `"cmd.exe" /c reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe" /t REG_SZ /d C:\Windows\System32\notepad.exe /f`
3. **Registry modification**: Sysmon EID 1 captures reg.exe (PID 12124) with the identical command line showing the actual registry write operation
4. **Process access events**: Sysmon EID 10 events show PowerShell accessing both spawned processes with full access rights (0x1FFFFF)

Security event logs complement this with EID 4688 process creation events for both cmd.exe and reg.exe, including the full command lines. The reg.exe process exits successfully (exit status 0x0) indicating the registry modification completed.

The attack successfully redirects `msedge.exe` execution to point to `C:\Windows\System32\notepad.exe` instead of the legitimate Microsoft Edge browser, demonstrating a working application hijacking scenario.

## What This Dataset Does Not Contain

The dataset lacks the most critical evidence for T1112 detection: **registry modification events**. There are no Sysmon EID 13 (Registry value set) or EID 12 (Registry object added) events, which would directly show the registry write to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe`. This absence suggests the sysmon-modular configuration may not be monitoring this specific registry path, representing a significant gap in registry monitoring coverage.

Additionally, the dataset doesn't contain verification of the attack's success through subsequent execution of the hijacked application path. No events show an attempt to launch `msedge.exe` to demonstrate the redirection working.

The PowerShell channel contains only standard test framework boilerplate (`Set-ExecutionPolicy Bypass` and error handling scriptblocks) without capturing the actual PowerShell commands that initiated the attack sequence.

## Assessment

This dataset provides moderate value for detection engineering, primarily through process-based detection opportunities rather than direct registry monitoring. The complete process chain from PowerShell to reg.exe with full command-line arguments offers solid behavioral indicators, but the absence of registry modification events significantly limits its utility for building comprehensive T1112 detections.

The data sources present (Security 4688 and Sysmon process events) are excellent for detecting the execution method but miss the core technique evidence. For a registry modification technique, this represents a critical blind spot that would require additional registry monitoring configuration to address.

## Detection Opportunities Present in This Data

1. **Registry tool execution with App Paths targeting**: Monitor Sysmon EID 1 or Security EID 4688 for reg.exe processes with command lines containing `"App Paths"` and specific application names like `msedge.exe`, `chrome.exe`, or other commonly targeted browsers.

2. **PowerShell spawning registry modification tools**: Alert on PowerShell processes (PID 13984) spawning cmd.exe which then launches reg.exe, indicating potential scripted registry manipulation.

3. **Command-line pattern for App Paths hijacking**: Detect reg.exe command lines matching the pattern `reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\*" /t REG_SZ /d * /f` which indicates application path redirection attempts.

4. **Process access anomalies**: Monitor Sysmon EID 10 events where PowerShell accesses recently spawned reg.exe processes with full access rights, potentially indicating process injection or monitoring capabilities.

5. **Suspicious registry tool parent processes**: Alert on reg.exe launched from non-administrative contexts or through script interpreters (PowerShell, cmd.exe) when modifying HKLM registry hives, especially with the `/f` force flag.

6. **Application path redirection to system binaries**: Detect registry modifications where legitimate application paths are redirected to generic system utilities like notepad.exe, calc.exe, or cmd.exe, which may indicate testing or preparation for payload deployment.
