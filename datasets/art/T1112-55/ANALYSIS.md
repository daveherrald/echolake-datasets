# T1112-55: Modify Registry — Do Not Connect To Win Update

## Technique Context

T1112 (Modify Registry) is a fundamental technique where adversaries modify Windows registry keys to establish persistence, evade defenses, or disable security features. The registry serves as Windows' central configuration database, making it a prime target for attackers seeking to alter system behavior.

This specific test modifies the `DoNotConnectToWindowsUpdateInternetLocations` registry value under `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`. When set to 1, this policy prevents Windows Update from connecting to internet locations for updates, forcing reliance on local WSUS servers or disabling updates entirely. Adversaries use this technique to prevent systems from receiving security patches, maintaining persistence in compromised environments.

The detection community focuses on monitoring registry modifications to sensitive keys, particularly those affecting security controls, update mechanisms, and system policies. Direct registry manipulation via reg.exe is considered high-confidence evidence of administrative-level system modification.

## What This Dataset Contains

This dataset captures the complete execution chain of a PowerShell-initiated registry modification. The technique executes through the process chain: `powershell.exe` → `cmd.exe` → `reg.exe`.

Key Security event evidence includes Security 4688 process creation events showing the full command line: `"cmd.exe" /c reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /t REG_DWORD /d 1 /f` and the subsequent `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /t REG_DWORD /d 1 /f`.

Sysmon provides complementary evidence with EID 1 ProcessCreate events for both cmd.exe and reg.exe, including full command lines and parent process relationships. The reg.exe process (PID 3788) shows the exact registry modification command being executed.

The Security channel also captures Security 4689 process termination events with exit status 0x0 for both cmd.exe and reg.exe, indicating successful execution.

PowerShell events show typical test framework boilerplate with Set-ExecutionPolicy calls but no script block content related to the actual registry modification, as the technique uses cmd.exe as an intermediary.

## What This Dataset Does Not Contain

Notably absent are Sysmon EID 13 (Registry value set) events that would directly capture the registry modification itself. The sysmon-modular configuration may not include registry monitoring for this specific key path, or the events may have been filtered out.

No Sysmon EID 12 (Registry object added or deleted) events appear, which would show the creation of the registry key structure if it didn't previously exist.

The dataset lacks any Windows Defender blocking or detection events, indicating this registry modification was not flagged as malicious by the endpoint protection solution.

No PowerShell script block logging captures the actual registry modification command, as the technique uses cmd.exe rather than native PowerShell registry cmdlets.

## Assessment

This dataset provides excellent process execution telemetry for detecting registry modification attempts through command-line tools. The Security 4688 events with full command-line logging offer high-fidelity detection opportunities, while Sysmon EID 1 events provide process lineage and timing correlation.

The absence of direct registry modification events (Sysmon EID 13) is a limitation for comprehensive detection coverage. However, the process-based evidence is sufficient for most detection scenarios, as the command line clearly indicates the intent and target of the registry modification.

The dataset would be stronger with registry modification events enabled in the Sysmon configuration, providing direct evidence of the registry change completion rather than just the attempt.

## Detection Opportunities Present in This Data

1. **Process creation of reg.exe with registry modification arguments** - Security 4688 and Sysmon EID 1 events showing reg.exe execution with "add" operations targeting sensitive registry keys

2. **Command line analysis for Windows Update policy modification** - Detection of command lines containing "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" and "DoNotConnectToWindowsUpdateInternetLocations"

3. **Process chain analysis for PowerShell-initiated system modification** - Correlation of PowerShell spawning cmd.exe which subsequently launches reg.exe, indicating potential scripted system modification

4. **Registry key targeting Windows Update functionality** - Monitoring for modifications to Windows Update policy registry paths, particularly those that could disable security updates

5. **Administrative privilege registry modification detection** - Process creation events showing registry modifications to HKLM requiring administrative privileges, executed by SYSTEM account

6. **Suspicious process lineage from PowerShell** - Detection of PowerShell processes spawning command-line utilities for system configuration changes rather than using native PowerShell cmdlets
