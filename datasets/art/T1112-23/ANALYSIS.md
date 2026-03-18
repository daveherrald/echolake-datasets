# T1112-23: Modify Registry — Activate Windows NoClose Group Policy Feature

## Technique Context

T1112 (Modify Registry) involves adversaries making changes to the Windows registry to hide configuration information, remove information as part of cleaning up, or alter system behavior for defense evasion and persistence. This specific test activates the Windows NoClose Group Policy feature, which prevents users from closing certain windows or applications through normal UI methods. While this particular modification might seem benign, the technique demonstrates how attackers can manipulate Windows group policy settings stored in the registry to control system behavior and potentially hinder incident response or system administration activities.

The detection community focuses on monitoring registry modifications to sensitive areas, especially policy-related keys under `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\` and `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\`. These locations are frequently targeted by malware for persistence mechanisms, security control bypasses, and system behavior modifications.

## What This Dataset Contains

This dataset captures a straightforward registry modification executed through PowerShell spawning cmd.exe to run reg.exe. The core execution chain shows:

1. **PowerShell execution**: Security 4688 shows `powershell.exe` spawning with command line execution
2. **Command shell spawning**: Security 4688 captures `cmd.exe /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoClose /t REG_DWORD /d 1 /f`
3. **Registry tool execution**: Security 4688 shows `reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoClose /t REG_DWORD /d 1 /f`

The Sysmon data provides complementary process creation events with Sysmon EID 1 for the same process chain. The reg.exe execution is captured as ProcessId 32936 with rule name `technique_id=T1012,technique_name=Query Registry`, though this is technically a registry modification rather than a query operation. Process access events (Sysmon EID 10) show PowerShell accessing both whoami.exe and cmd.exe with full access (0x1FFFFF).

The PowerShell channel contains only standard test framework boilerplate with Set-ExecutionPolicy Bypass commands and framework initialization scriptblocks, providing no technique-specific command content.

## What This Dataset Does Not Contain

This dataset lacks the most critical telemetry for registry modification detection: actual registry change events. Windows does not generate Security events for registry modifications by default, and the Sysmon configuration used here does not include registry monitoring (EID 12, 13, 14). This means while we can see the reg.exe execution, we cannot confirm the registry modification actually occurred or capture the specific key/value changes.

The dataset also lacks process creation events for the parent PowerShell processes in Sysmon, likely filtered out by the include-mode ProcessCreate configuration since PowerShell execution wasn't matching the suspicious process patterns.

## Assessment

This dataset provides moderate value for building process-based detections around registry modification tools but significant limitations for comprehensive registry monitoring. The Security 4688 events with command-line logging effectively capture the complete execution chain and the specific registry modification command, which is the most actionable detection data present.

The combination of PowerShell spawning cmd.exe spawning reg.exe with policy-related registry paths in the command line provides good detection opportunities. However, the absence of actual registry change telemetry means defenders cannot validate successful execution or monitor for more subtle registry modifications that don't use command-line tools.

For production environments focused on T1112 detection, this dataset highlights the critical need for registry monitoring through Sysmon registry events or other endpoint detection capabilities that can capture actual registry modifications rather than relying solely on process execution patterns.

## Detection Opportunities Present in This Data

1. **Policy registry modification via reg.exe**: Security 4688 command lines containing `reg add` with paths to `\Policies\` registry keys, particularly HKCU and HKLM policy locations

2. **PowerShell-to-cmd-to-reg process chain**: Sequence of Security 4688 events showing powershell.exe spawning cmd.exe spawning reg.exe within short time windows

3. **Specific NoClose policy activation**: Command line pattern `reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoClose` indicating UI control manipulation

4. **Registry tool execution from scripting contexts**: Sysmon EID 1 showing reg.exe execution with parent processes of cmd.exe or powershell.exe, especially with policy-related arguments

5. **Cross-process access to registry tools**: Sysmon EID 10 showing PowerShell accessing cmd.exe or reg.exe processes with high privileges (0x1FFFFF access rights)

6. **Batch registry operations**: Command line usage of reg.exe with `/f` (force) flag combined with policy registry paths, indicating automated/scripted registry modification attempts
