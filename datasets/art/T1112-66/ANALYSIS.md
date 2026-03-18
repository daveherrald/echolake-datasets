# T1112-66: Modify Registry — WER

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries modify Windows registry settings to alter system behavior, disable security controls, or establish persistence mechanisms. This specific test targets Windows Error Reporting (WER) by setting the `DontShowUI` registry value, which suppresses error reporting dialogs that could alert users to application crashes or system issues. Attackers commonly disable WER to reduce visibility into their activities, particularly when their tools or payloads cause application instability. The detection community focuses on registry modifications to security-relevant keys, especially those that disable logging, reporting, or monitoring capabilities.

## What This Dataset Contains

The dataset captures a complete process chain executing the registry modification via PowerShell and command-line tools. Security event 4688 shows the full command line: `"cmd.exe" /c reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v DontShowUI /t REG_DWORD /d 1 /f`. The process chain flows from PowerShell (PID 35572) → cmd.exe (PID 35836) → reg.exe (PID 17700), with all processes running as NT AUTHORITY\SYSTEM.

Sysmon provides complementary telemetry with ProcessCreate events for the key executables. Event ID 1 captures whoami.exe execution for reconnaissance, cmd.exe with the full registry command, and reg.exe with the identical command line parameters. Process access events (EID 10) show PowerShell accessing both child processes with full access rights (0x1FFFFF).

The PowerShell channel contains only boilerplate test framework activity - Set-StrictMode and Set-ExecutionPolicy Bypass commands - but no script blocks containing the actual technique implementation, indicating the test likely used direct command execution rather than PowerShell scripting.

## What This Dataset Does Not Contain

Notably absent is the actual registry modification event. While the reg.exe process executed successfully (exit status 0x0 in Security 4689), there are no Sysmon EID 13 (RegistryEvent) entries capturing the creation of the `HKCU\Software\Microsoft\Windows\Windows Error Reporting\DontShowUI` value. This absence likely stems from the sysmon-modular configuration filtering registry events, as object access auditing is disabled (`object_access: none`) and Sysmon registry monitoring may be limited to specific high-value keys.

The dataset also lacks any Windows Defender alerts or blocks, suggesting this registry modification doesn't trigger behavioral detection rules, even though it represents a clear defensive evasion technique.

## Assessment

This dataset provides excellent process execution telemetry but critical gaps in registry modification evidence. The Security and Sysmon ProcessCreate events offer strong detection opportunities for the command-line patterns and process relationships. However, without registry event logs, you cannot definitively prove the technique succeeded or build detections around the actual registry modification. For comprehensive T1112 detection engineering, you would need additional data sources like Registry auditing or enhanced Sysmon registry monitoring targeting WER-related keys.

The clean process chain and detailed command-line logging make this dataset valuable for testing process-based detections, but insufficient for registry-focused detection logic.

## Detection Opportunities Present in This Data

1. **Registry utility execution with WER paths** - Security 4688 and Sysmon EID 1 showing reg.exe with command lines containing "Windows Error Reporting" and "DontShowUI" parameters
2. **PowerShell spawning reg.exe** - Process chain analysis showing powershell.exe → cmd.exe → reg.exe with registry modification arguments
3. **System context registry modifications** - All processes running as NT AUTHORITY\SYSTEM attempting to modify user registry hives (HKCU), which is anomalous
4. **WER disabling command patterns** - Command line detection for `reg add` operations targeting the Windows Error Reporting registry key with DontShowUI value
5. **Process access patterns** - Sysmon EID 10 showing PowerShell obtaining full access (0x1FFFFF) to registry utility processes, indicating potential process manipulation
