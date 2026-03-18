# T1112-32: Modify Registry — Windows Modify Show Compress Color And Info Tip Registry

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries modify Windows registry keys and values to evade detection, maintain persistence, or alter system behavior. This specific test focuses on modifying Windows Explorer's advanced settings to disable file information tooltips (`ShowInfoTip`) and compressed file color highlighting (`ShowCompColor`). While these particular registry modifications are relatively benign, they represent a common pattern where adversaries modify Explorer settings to reduce visual indicators that might expose their activities. Detection engineers focus on registry modification patterns, especially when performed by unexpected processes or targeting security-relevant keys. The reg.exe utility is frequently monitored as it's a common tool for both legitimate administration and malicious registry manipulation.

## What This Dataset Contains

This dataset captures a PowerShell-initiated registry modification sequence targeting Windows Explorer display settings. The core activity shows in Security event 4688 with cmd.exe spawning with the command line `"cmd.exe" /c reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowInfoTip /t REG_DWORD /d 0 /f & reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowCompColor /t REG_DWORD /d 0 /f`. This spawns two sequential reg.exe processes with Sysmon ProcessCreate events showing `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowInfoTip /t REG_DWORD /d 0 /f` and `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowCompColor /t REG_DWORD /d 0 /f`. The process tree shows powershell.exe → cmd.exe → reg.exe (twice), with all processes running as NT AUTHORITY\SYSTEM and exiting cleanly with status 0x0. Sysmon also captures process access events (EID 10) showing PowerShell accessing both spawned processes with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

Notably absent are Sysmon registry modification events (EID 13), which would directly show the registry keys and values being written. This suggests the sysmon-modular configuration may not be capturing registry modifications to the specific HKCU\Explorer\Advanced path, or these events were filtered. The dataset also lacks any registry query events that might show the technique reading existing values before modification. No network events are present since this is a local registry operation. The PowerShell channel contains only standard test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual PowerShell commands that initiated the registry changes, indicating the test likely used Invoke-Expression or similar indirect execution methods.

## Assessment

This dataset provides good coverage for process-based detection of registry modification techniques through the complete process execution chain. The Security 4688 events with command-line logging capture the exact registry operations being performed, while Sysmon ProcessCreate events (EID 1) provide additional context with file hashes and process relationships. The process access events (EID 10) add behavioral context showing PowerShell's interaction with the spawned processes. However, the absence of direct registry modification telemetry (Sysmon EID 13) limits the dataset's utility for building registry-focused detections. For detection engineering, this dataset is most valuable for identifying suspicious use of reg.exe and command-line patterns rather than direct registry monitoring approaches.

## Detection Opportunities Present in This Data

1. **Reg.exe execution with specific registry paths** - Security 4688 and Sysmon EID 1 showing reg.exe targeting `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` with ShowInfoTip or ShowCompColor modifications

2. **Command-line chaining patterns** - Security 4688 capturing cmd.exe with compound commands using "&" to chain multiple reg.exe operations in sequence

3. **PowerShell spawning registry modification utilities** - Process tree analysis showing powershell.exe → cmd.exe → reg.exe execution chains, particularly when modifying Explorer settings

4. **Registry modification via indirect execution** - PowerShell launching cmd.exe to execute reg.exe rather than using native PowerShell registry cmdlets, indicating potential evasion attempts

5. **Process access patterns during registry operations** - Sysmon EID 10 showing PowerShell accessing spawned reg.exe processes with full rights (0x1FFFFF), which could indicate process monitoring or result collection

6. **Sequential registry operations** - Multiple reg.exe processes with overlapping timestamps targeting the same registry hive, suggesting scripted or automated registry modification campaigns

7. **System-level registry modifications** - Registry changes performed by NT AUTHORITY\SYSTEM context, which may indicate privilege escalation or administrative tool abuse
