# T1218-14: System Binary Proxy Execution — Provlaunch.exe Executes Arbitrary Command via Registry Key

## Technique Context

T1218 System Binary Proxy Execution encompasses attackers leveraging legitimate Windows binaries to execute malicious code while evading detection. The provlaunch.exe technique (T1218.014) specifically exploits Windows Provisioning Launch, a binary designed to execute commands defined in the registry under `HKLM\SOFTWARE\Microsoft\Provisioning\Commands`. Attackers can write malicious commands to this registry location and use provlaunch.exe to execute them, effectively using a trusted Windows binary as a proxy for code execution.

This technique is particularly valuable for defense evasion because provlaunch.exe is a legitimate Microsoft binary that's less likely to trigger security alerts. The detection community focuses on monitoring registry writes to the Provisioning\Commands path, unusual parent-child process relationships involving provlaunch.exe, and command-line arguments that reference custom registry keys.

## What This Dataset Contains

This dataset captures a complete execution chain demonstrating the provlaunch.exe technique. The Security channel (EID 4688) shows the full command sequence: `"cmd.exe" /c reg.exe add HKLM\SOFTWARE\Microsoft\Provisioning\Commands\LOLBin\dummy1 /v altitude /t REG_DWORD /d 0 & reg add HKLM\SOFTWARE\Microsoft\Provisioning\Commands\LOLBin\dummy1\dummy2 /v Commandline /d calc.exe & c:\windows\system32\provlaunch.exe LOLBin`.

The process chain is clearly visible across Security 4688 events:
1. PowerShell spawns cmd.exe with the composite command
2. cmd.exe spawns two reg.exe processes to set up the registry structure
3. cmd.exe spawns provlaunch.exe with argument "LOLBin"  
4. provlaunch.exe spawns calc.exe as the payload

Sysmon captures the provlaunch.exe execution without a ProcessCreate event (due to include-mode filtering), but calc.exe appears as a Sysmon EID 1 with parent process `C:\Windows\System32\provlaunch.exe` and command line `calc.exe`. The Sysmon events also show the reg.exe processes (EID 1) with their full command lines for registry manipulation.

## What This Dataset Does Not Contain

The dataset lacks registry modification events - neither Sysmon EID 13 (Registry value set) nor Security EID 4657 (Registry value modified) events appear, likely due to the audit policy configuration not including object access auditing. This is a significant gap since registry writes to the Provisioning\Commands path are a key detection point for this technique.

There are no Sysmon ProcessCreate events for the cmd.exe or provlaunch.exe processes themselves due to the sysmon-modular include-mode filtering, though their execution is still captured via Security 4688 events with full command lines. The PowerShell channel contains only test framework boilerplate (Set-ExecutionPolicy Bypass calls) rather than the actual attack commands.

## Assessment

This dataset provides excellent visibility into the process execution chain for the provlaunch.exe technique through Security 4688 events with command-line logging. The parent-child relationships are clear, and both the registry setup commands and the final provlaunch.exe execution are well-documented. However, the absence of registry modification telemetry significantly limits detection engineering opportunities, as the registry writes are typically the earliest and most reliable detection point for this technique.

The combination of Security process creation events and selective Sysmon ProcessCreate events (capturing the final calc.exe payload) provides sufficient telemetry for process-based detections, but defenders would need additional data sources for comprehensive coverage of the registry manipulation component.

## Detection Opportunities Present in This Data

1. **Provlaunch.exe execution with custom arguments** - Security 4688 showing provlaunch.exe with non-standard command line arguments (e.g., "LOLBin" instead of typical provisioning package names)

2. **Registry manipulation preceding provlaunch.exe** - Sequential reg.exe executions targeting HKLM\SOFTWARE\Microsoft\Provisioning\Commands followed by provlaunch.exe execution within a short timeframe

3. **Unusual parent process for provlaunch.exe** - cmd.exe spawning provlaunch.exe, which deviates from typical provisioning workflows where provlaunch.exe is called by system processes

4. **Suspicious process chain pattern** - PowerShell → cmd.exe → reg.exe (multiple) → provlaunch.exe → arbitrary executable sequence within seconds

5. **Calc.exe spawned by provlaunch.exe** - Sysmon EID 1 showing calc.exe with provlaunch.exe as parent, which is unusual since calc.exe typically launches from explorer.exe or user-initiated processes

6. **Command line containing Provisioning\Commands registry path** - Detection on command lines referencing the specific registry path used by this technique

7. **Multiple reg.exe processes with HKLM\SOFTWARE\Microsoft\Provisioning\Commands targets** - Security 4688 events showing reg.exe processes writing to the provisioning commands registry location
