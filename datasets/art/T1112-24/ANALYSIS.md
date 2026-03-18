# T1112-24: Modify Registry — Activate Windows NoSetTaskbar Group Policy Feature

## Technique Context

T1112 (Modify Registry) is a fundamental technique where adversaries alter Windows registry settings to establish persistence, evade defenses, or modify system behavior. The Windows registry serves as a hierarchical database storing low-level settings for the operating system and applications. Attackers frequently target Group Policy-related registry keys to disable security features, modify user interface elements, or establish persistence mechanisms that survive reboots.

The specific technique demonstrated here targets the `NoSetTaskbar` Group Policy setting, which prevents users from modifying taskbar settings. While this particular setting appears benign, it demonstrates the broader pattern of registry-based Group Policy manipulation that adversaries use for more malicious purposes like disabling Windows Defender, modifying firewall settings, or establishing persistence through registry autorun keys. Detection engineers focus on monitoring registry modifications to sensitive keys, particularly those under `HKLM\Software\Policies` and `HKCU\Software\Policies` where Group Policy settings are stored.

## What This Dataset Contains

This dataset captures a straightforward registry modification attack using the `reg.exe` utility. The attack chain begins with PowerShell (PID 33048) spawning cmd.exe with the command line `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSetTaskbar /t REG_DWORD /d 1 /f`. The cmd.exe process (PID 33312) then executes reg.exe (PID 32916) with the full registry modification command: `reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSetTaskbar /t REG_DWORD /d 1 /f`.

The Security channel captures this process chain clearly in EID 4688 events, showing the parent-child relationships: powershell.exe → cmd.exe → reg.exe. All processes execute under NT AUTHORITY\SYSTEM with TokenElevationTypeDefault (1), indicating full administrative privileges. Sysmon EID 1 events provide additional context with process GUIDs, hashes, and integrity levels confirming system-level execution.

The dataset also includes typical PowerShell test framework telemetry in the PowerShell channel (Set-ExecutionPolicy Bypass, Set-StrictMode) and process termination events (Security EID 4689) showing clean exit status 0x0 for all components, indicating successful execution.

## What This Dataset Does Not Contain

Critically, this dataset lacks the actual registry modification telemetry. There are no Sysmon EID 13 (RegistryEvent - Value Set) events capturing the creation of the `NoSetTaskbar` DWORD value. This absence suggests either the sysmon-modular configuration filters out this specific registry path, or the registry modification was blocked/failed despite the clean process exit codes.

The dataset also lacks any Windows Defender alerts or blocking events, despite the endpoint protection being active. This indicates either the technique was allowed to proceed or was considered benign behavior. Additionally, there are no Object Access audit events (Security EID 4656/4658) that would show registry handle operations, likely because object access auditing is disabled per the environment configuration.

## Assessment

This dataset provides excellent process execution telemetry but limited evidence of the actual registry modification impact. The Security 4688 events with command-line logging offer comprehensive visibility into the attack chain, making this technique easily detectable through process monitoring. The Sysmon data adds valuable context with process relationships and file hashes.

However, the absence of registry modification events significantly limits the dataset's utility for understanding the technique's full impact. Detection engineers can build robust process-based detections from this data, but cannot validate whether the registry change actually occurred or develop registry-focused detection rules. The dataset would be substantially stronger with Sysmon registry events or Windows Event Log registry auditing enabled.

## Detection Opportunities Present in This Data

1. **Process chain analysis**: Detect PowerShell spawning cmd.exe with reg.exe command lines containing policy-related registry paths (`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies`)

2. **Registry utility abuse**: Monitor for reg.exe executions with "add" operations targeting Group Policy registry locations, particularly when spawned by scripting engines

3. **Command line pattern matching**: Alert on cmd.exe command lines containing specific patterns like `/c reg add` combined with policy registry paths and force flags (`/f`)

4. **Parent process analysis**: Flag reg.exe processes with unexpected parents (PowerShell, cmd.exe from scripting contexts) rather than typical administrative tools

5. **Group Policy tampering detection**: Monitor for any registry modifications under `Software\*\Policies` paths, especially when performed by non-Group Policy management processes

6. **Process elevation context**: Detect registry modification tools running with SYSTEM privileges when initiated through script execution chains
