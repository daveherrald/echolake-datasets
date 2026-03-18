# T1218-11: System Binary Proxy Execution — Lolbin Gpscript startup option

## Technique Context

T1218 System Binary Proxy Execution involves adversaries leveraging legitimate, signed binaries to proxy execution of malicious code. The gpscript.exe binary is a lesser-known Windows utility designed for Group Policy script execution. When invoked with the `/startup` parameter, gpscript.exe can be abused to execute arbitrary code while appearing as a legitimate Windows process. This technique helps attackers evade application whitelisting controls and blend into normal system operations. Detection engineers typically focus on unusual command-line arguments to legitimate binaries, process relationships, and spawning patterns that deviate from normal administrative usage.

## What This Dataset Contains

The dataset captures a successful execution of the gpscript.exe LOLBin technique through the following process chain:

- **Initial PowerShell execution**: Security event 4688 shows `powershell.exe` (PID 7840) as the parent process
- **Command shell intermediary**: Security event 4688 captures `cmd.exe /c Gpscript /startup` (PID 1628) spawned by PowerShell
- **Target binary execution**: Security event 4688 shows `gpscript.exe /startup` (PID 26920) executed by cmd.exe

The Sysmon data provides additional context with EID 1 ProcessCreate events showing the exact command lines:
- `"cmd.exe" /c Gpscript /startup` 
- `Gpscript /startup`

The dataset includes typical PowerShell test framework telemetry in the PowerShell channel (EID 4103 Set-ExecutionPolicy, EID 4104 scriptblocks), along with Sysmon image loads (EID 7) and process access events (EID 10). Security events 4689 show all processes exiting cleanly with status 0x0, indicating successful execution.

## What This Dataset Does Not Contain

The dataset lacks evidence of what gpscript.exe actually executed during its runtime. There are no child processes spawned by gpscript.exe, no file modifications, network connections, or registry changes captured in the available telemetry. This suggests either the technique executed without generating additional observable artifacts, or Windows Defender's real-time protection may have limited the binary's capabilities. The Sysmon ProcessCreate events for gpscript.exe itself are captured because the sysmon-modular config includes gpscript.exe as a known LOLBin, but any potential child processes would depend on whether they matched the include-mode filtering patterns.

## Assessment

This dataset provides excellent foundational telemetry for detecting gpscript.exe abuse. The Security channel's 4688 events with command-line logging capture the complete execution chain clearly, while Sysmon EID 1 events provide additional process relationship context with GUIDs and hashes. The presence of the `/startup` parameter in both the cmd.exe and gpscript.exe command lines creates strong detection opportunities. However, the dataset's value is somewhat limited by the lack of post-execution activity, which would help analysts understand the technique's impact and develop more comprehensive detection coverage.

## Detection Opportunities Present in This Data

1. **Gpscript.exe execution with startup parameter** - Security EID 4688 showing `gpscript.exe` with `/startup` command-line argument
2. **Unusual gpscript.exe parent process** - Process relationship where gpscript.exe is spawned by cmd.exe rather than legitimate Group Policy services
3. **Command shell proxy pattern** - cmd.exe executing with `/c Gpscript /startup` parameter from PowerShell parent
4. **LOLBin process creation** - Sysmon EID 1 capturing gpscript.exe execution with full process metadata and hashes
5. **PowerShell-initiated LOLBin chain** - Process tree showing powershell.exe → cmd.exe → gpscript.exe execution sequence
6. **Interactive gpscript.exe execution** - gpscript.exe running in user context rather than system service context during startup/logon
