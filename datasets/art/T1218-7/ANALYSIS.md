# T1218-7: System Binary Proxy Execution — Invoke-ATHRemoteFXvGPUDisablementCommand base test

## Technique Context

System Binary Proxy Execution (T1218) is a defense evasion technique where attackers leverage legitimate, signed Windows binaries to proxy execution of malicious code, bypassing application control policies and execution restrictions. The Atomic Red Team test T1218-7 specifically targets the `Invoke-ATHRemoteFXvGPUDisablementCommand` function, which is designed to simulate abuse of Windows binary proxying capabilities. This technique is particularly valuable to attackers because it allows them to execute code through trusted system processes, making detection more challenging. Detection engineers typically focus on unusual command-line parameters, unexpected child processes from system binaries, and abnormal process relationships when hunting for T1218 abuse.

## What This Dataset Contains

This dataset captures a PowerShell-based execution chain invoking the `Invoke-ATHRemoteFXvGPUDisablementCommand` function. The Security channel shows the primary process creation with command line `"powershell.exe" & {Invoke-ATHRemoteFXvGPUDisablementCommand -ModuleName foo -ModulePath $PWD}` (EID 4688), along with a `whoami.exe` execution spawned from the PowerShell process. The PowerShell operational log contains script block logging (EID 4104) showing the function invocation: `{Invoke-ATHRemoteFXvGPUDisablementCommand -ModuleName foo -ModulePath $PWD}`. Sysmon data provides detailed process creation events for both the PowerShell process (ProcessId 25644) and whoami.exe (ProcessId 39836), along with extensive image loading events showing .NET runtime components and Windows Defender modules loading into the PowerShell processes. The dataset also captures process access events (EID 10) showing PowerShell accessing both the whoami.exe process and another PowerShell process with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

The dataset lacks evidence of actual system binary proxy execution - the test appears to invoke a custom PowerShell function rather than demonstrating abuse of a legitimate Windows binary like regsvr32.exe, rundll32.exe, or similar LOLBins commonly associated with T1218. There's no registry modification, file system artifacts beyond PowerShell startup profiles, or network activity that would typically accompany more sophisticated proxy execution techniques. The Sysmon process creation events are limited due to the sysmon-modular include-mode filtering, which may have filtered out some intermediate processes. Additionally, there's no evidence of the technique actually succeeding in proxying execution through a system binary - this appears to be a benign test framework execution rather than a realistic T1218 simulation.

## Assessment

This dataset provides limited value for detecting actual T1218 System Binary Proxy Execution techniques. While it contains good telemetry for PowerShell execution and process relationships, it doesn't demonstrate the core behavior of T1218 - using legitimate system binaries to proxy malicious code execution. The Security channel's process creation events with command-line logging provide the clearest detection opportunity, but the technique being tested doesn't align with typical T1218 attack patterns. The Sysmon data is comprehensive for PowerShell analysis but lacks the system binary abuse that defines T1218. Detection engineers would be better served by datasets showing actual abuse of Windows binaries like regsvr32, mshta, or rundll32 with suspicious parameters.

## Detection Opportunities Present in This Data

1. **PowerShell Command Line Analysis** - Security EID 4688 captures the full command line with the suspicious function name `Invoke-ATHRemoteFXvGPUDisablementCommand`, which could trigger on ATT&CK-related function names
2. **PowerShell Script Block Content** - PowerShell EID 4104 events contain the actual function invocation that could be detected via script block logging rules
3. **Process Relationship Monitoring** - Sysmon EID 1 events show PowerShell spawning whoami.exe, indicating potential reconnaissance activity
4. **Cross-Process Access Detection** - Sysmon EID 10 events capture PowerShell accessing other processes with full rights, potentially indicating injection attempts
5. **PowerShell Execution Context** - Multiple PowerShell processes (PIDs 39848, 36512, 25644, 26316) spawning in sequence could indicate scripted or automated execution
