# T1112-2: Modify Registry — Modify Registry of Local Machine - cmd

## Technique Context

T1112 (Modify Registry) is a fundamental persistence and defense evasion technique where adversaries modify Windows registry keys to achieve their objectives. Registry modification is one of the most common persistence mechanisms on Windows, allowing attackers to maintain access across reboots, disable security controls, or alter system behavior. The detection community focuses heavily on monitoring specific high-value registry locations like Run keys, service configurations, and security policy settings. This particular test demonstrates using cmd.exe to execute reg.exe for adding a persistence entry to HKLM\Software\Microsoft\Windows\CurrentVersion\Run, which is a classic autostart mechanism that executes programs when any user logs in.

## What This Dataset Contains

This dataset captures a successful registry modification operation executed through a command shell. The core activity shows PowerShell (PID 30956) spawning cmd.exe with the command line `"cmd.exe" /c reg add HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run /t REG_EXPAND_SZ /v SecurityHealth /d calc.exe /f`. The cmd.exe process (PID 22100) then launches reg.exe (PID 30560) with the arguments `reg add HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run /t REG_EXPAND_SZ /v SecurityHealth /d calc.exe /f`.

The critical telemetry appears in Sysmon EID 13, showing the actual registry modification: `Registry value set: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth` with the value `calc.exe`. Security EID 4688 events capture the complete process chain with full command lines, showing PowerShell → cmd.exe → reg.exe. All processes exit successfully with status 0x0, confirming the operation completed without errors.

Additionally, the dataset includes Sysmon EID 1 events for both cmd.exe and reg.exe creation, providing process hashes, parent-child relationships, and integrity levels (all running as NT AUTHORITY\SYSTEM with System integrity).

## What This Dataset Does Not Contain

The dataset lacks several registry-related telemetry sources that would provide additional detection opportunities. Windows Security event 4657 (registry value was modified) is not present, likely because object access auditing for registry keys is not enabled in the audit policy. The dataset also doesn't contain any Windows Defender or AMSI events, suggesting this registry modification was not flagged as suspicious by endpoint protection.

Sysmon process creation events for the parent PowerShell processes are missing due to the sysmon-modular configuration's include-mode filtering, which only captures processes matching suspicious patterns. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy) rather than the actual script content that initiated the registry modification.

## Assessment

This dataset provides excellent coverage for detecting T1112 registry modification activities. The combination of Sysmon EID 13 registry monitoring with Security EID 4688 process auditing creates a complete picture of both the mechanism (reg.exe) and the result (registry value creation). The presence of full command lines in process creation events enables detection of specific registry paths and values being modified. The Sysmon registry monitoring specifically targeting Run keys (technique_id=T1547.001 in the RuleName) demonstrates purpose-built detection coverage for this persistence mechanism.

The data quality is high with complete process chains, exit codes, and precise timestamps. The registry modification telemetry includes the exact target object path and value, enabling both broad detection of Run key modifications and specific detection of the "SecurityHealth" value name used in this test.

## Detection Opportunities Present in This Data

1. **Sysmon EID 13 monitoring for HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run modifications** - Direct detection of persistence establishment via Run keys

2. **Security EID 4688 process creation of reg.exe with "add" and "Run" arguments** - Command-line analysis to detect registry modification tools targeting autostart locations

3. **Process chain analysis of cmd.exe spawning reg.exe** - Pattern detection for indirect registry modification through command shell

4. **Registry value name "SecurityHealth" detection** - Potential impersonation of legitimate Windows Security Health service

5. **Combination of process creation and registry modification correlation** - Join Sysmon EID 1 and EID 13 events by ProcessGuid to detect successful registry persistence operations

6. **PowerShell spawning cmd.exe for registry operations** - Detection of PowerShell-initiated registry modifications through command shell indirection

7. **REG_EXPAND_SZ type monitoring** - Focus on expandable string registry types often used for executable paths in persistence mechanisms
