# T1112-39: Modify Registry — Allow RDP Remote Assistance Feature

## Technique Context

T1112 (Modify Registry) is a fundamental persistence and defense evasion technique where adversaries alter Windows registry values to maintain access or disable security controls. This specific test enables the Remote Desktop Protocol (RDP) Remote Assistance feature by setting the `fAllowToGetHelp` registry value to 1 in `HKLM\System\CurrentControlSet\Control\Terminal Server`. Remote Assistance allows external users to connect to and control a Windows system, making this a common persistence mechanism for attackers seeking to maintain remote access. Detection engineers typically focus on monitoring registry modifications to sensitive paths, especially those related to RDP configuration, system services, and security controls.

## What This Dataset Contains

The dataset captures a successful registry modification executed via PowerShell spawning cmd.exe and reg.exe. Security event 4688 shows the complete process chain: PowerShell (PID 15740) → cmd.exe (PID 13028) with command line `"cmd.exe" /c reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f` → reg.exe (PID 39236) with the actual registry modification command `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f`. 

Sysmon provides rich telemetry including ProcessCreate events (EID 1) for whoami.exe, cmd.exe, and reg.exe with full command lines, ProcessAccess events (EID 10) showing PowerShell accessing spawned processes with 0x1FFFFF access rights, and ImageLoaded events (EID 7) tracking .NET Framework and Windows Defender DLL loads. The PowerShell channel contains only test framework boilerplate with Set-ExecutionPolicy bypass commands rather than the actual technique execution script.

## What This Dataset Does Not Contain

Critically, this dataset lacks Sysmon registry modification events (EID 13) that would directly capture the registry value change to `fAllowToGetHelp`. This omission could be due to Sysmon configuration filtering that doesn't monitor the specific registry path or because the sysmon-modular config doesn't include this registry key in its monitoring scope. Additionally, there are no application events or other registry-specific logs that would confirm the actual registry modification occurred, only the process execution evidence showing the attempt.

## Assessment

This dataset provides excellent process execution telemetry for detecting the technique through command-line analysis and process relationships, but falls short on registry-specific evidence. The Security channel's command-line logging is the strongest detection source here, capturing the exact reg.exe command with suspicious RDP-related parameters. Sysmon ProcessCreate events complement this with parent-child relationships and process hashes. However, without registry modification events, defenders cannot definitively confirm the technique succeeded or monitor for similar registry changes across different execution methods. The dataset would be significantly stronger with Sysmon EID 13 events or Windows registry auditing enabled.

## Detection Opportunities Present in This Data

1. **Command-line pattern matching** - Security EID 4688 and Sysmon EID 1 both capture the reg.exe command line containing "Terminal Server" and "fAllowToGetHelp" strings that are highly specific to this technique

2. **Process chain analysis** - PowerShell spawning cmd.exe spawning reg.exe represents a suspicious execution pattern, especially when combined with registry modification commands

3. **Registry tool execution** - reg.exe execution from PowerShell contexts with Terminal Server-related arguments indicates potential RDP configuration tampering

4. **Process access monitoring** - Sysmon EID 10 shows PowerShell accessing child processes with full rights (0x1FFFFF), which could indicate process injection or monitoring capabilities

5. **PowerShell execution policy bypass** - PowerShell module logging captures Set-ExecutionPolicy bypass commands that often precede malicious script execution

6. **Parent process context** - Detection of reg.exe with PowerShell as grandparent process suggests scripted automation rather than administrative activity
