# T1112-84: Modify Registry — Modify UsePIN Registry entry

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries modify the Windows registry to hide configuration information, remove logging capabilities, or disable security controls. Registry modifications can persist across reboots and are commonly used by malware to maintain access or evade detection. This specific test modifies the BitLocker `UsePIN` policy setting in `HKLM\SOFTWARE\Policies\Microsoft\FVE`, which controls whether users can use a PIN to unlock BitLocker-encrypted drives. The detection community focuses on monitoring registry modifications to sensitive security policy locations, particularly those affecting encryption, authentication, and logging capabilities.

## What This Dataset Contains

This dataset captures a straightforward registry modification executed through PowerShell and cmd.exe. The key evidence includes:

**Process Chain**: PowerShell spawns cmd.exe which executes reg.exe with the command `reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UsePIN /t REG_DWORD /d 2 /f`. Security event 4688 shows the complete command line: `"cmd.exe" /c reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UsePIN /t REG_DWORD /d 2 /f`.

**Sysmon Process Creation**: Events capture the process creation chain with Sysmon EID 1 showing cmd.exe (PID 43344) spawning reg.exe (PID 26812). The reg.exe process is tagged with `RuleName: technique_id=T1012,technique_name=Query Registry`, indicating the sysmon-modular config correctly identifies registry operations.

**Process Access**: Sysmon EID 10 events show PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF), demonstrating the parent-child process relationship.

**PowerShell Activity**: Multiple Sysmon EID 7 events show PowerShell loading .NET runtime components and System.Management.Automation assemblies. PowerShell events 4103 and 4104 contain only test framework boilerplate (Set-ExecutionPolicy Bypass) with no actual technique-specific script content.

## What This Dataset Does Not Contain

**Registry Modification Evidence**: Notably absent are Sysmon EID 13 (Registry value set) events that would directly show the registry modification occurring. This is likely because the sysmon-modular configuration doesn't monitor the specific registry path `HKLM\SOFTWARE\Policies\Microsoft\FVE` or because registry monitoring wasn't configured for this location.

**Actual Registry Content**: The dataset doesn't contain evidence of the registry value being successfully written or the before/after state of the UsePIN setting.

**Enhanced PowerShell Logging**: The PowerShell events show only execution policy changes, not the actual commands that triggered the registry modification, suggesting the registry change was initiated through a different mechanism than direct PowerShell registry cmdlets.

## Assessment

This dataset provides good process-level telemetry for detecting registry modification attempts through command-line tools, but lacks the registry-specific telemetry that would provide complete visibility into the technique. The Security event 4688 process creation logs with command-line auditing are the strongest detection source here, clearly showing the reg.exe invocation with the specific registry path and value. The Sysmon process creation and process access events provide additional context about the execution chain. However, without Sysmon registry monitoring events, defenders would need to rely primarily on process monitoring to detect this technique variant.

## Detection Opportunities Present in This Data

1. Monitor Security EID 4688 for reg.exe executions targeting sensitive policy paths like `HKLM\SOFTWARE\Policies\Microsoft\FVE` or other BitLocker-related registry locations

2. Detect Sysmon EID 1 process creation events for reg.exe with command lines containing "add" operations to policy registry hives

3. Alert on process chains where PowerShell spawns cmd.exe which then executes reg.exe, indicating potential script-driven registry modification

4. Monitor for reg.exe executions with the `/f` (force) flag combined with policy registry paths, suggesting automated or scripted registry tampering

5. Track Sysmon EID 10 process access events where PowerShell accesses registry utilities like reg.exe with full access rights

6. Correlate multiple registry tool invocations from the same parent process to identify bulk policy modifications

7. Monitor for modifications to BitLocker policy settings specifically, as these could indicate attempts to weaken encryption controls
