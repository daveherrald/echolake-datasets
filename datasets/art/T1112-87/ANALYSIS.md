# T1112-87: Modify Registry — Abusing MyComputer Disk Cleanup Path for Persistence

## Technique Context

T1112 (Modify Registry) is a fundamental technique attackers use to alter Windows registry keys and values for defense evasion and persistence. This specific test (T1112-87) demonstrates a lesser-known persistence mechanism that abuses the Windows Explorer "MyComputer\cleanuppath" registry value. When this registry path is modified, it can cause Windows to execute the specified program when users interact with certain disk cleanup or computer management operations.

The detection community typically focuses on monitoring registry modifications to well-known persistence locations (Run keys, services, etc.), but this technique targets a more obscure registry path that may evade standard detection rules. The cleanuppath mechanism is particularly interesting because it can provide persistence that triggers during seemingly benign system maintenance activities.

## What This Dataset Contains

This dataset captures a successful registry modification attack executed via PowerShell calling cmd.exe and reg.exe. The core malicious activity is visible in Security event 4688 showing the process creation for:

`"cmd.exe" /c reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\cleanuppath" /t REG_EXPAND_SZ /d "%%systemroot%%\system32\notepad.exe" /f`

The attack follows this process chain:
- PowerShell (PID 9448) → cmd.exe (PID 8780) → reg.exe (PID 8644)

Sysmon captures three key ProcessCreate events:
- EID 1 for whoami.exe execution (reconnaissance)
- EID 1 for cmd.exe with the full malicious command line
- EID 1 for reg.exe showing the registry modification command with resolved path

The dataset also includes Sysmon EID 10 events showing PowerShell accessing both the whoami.exe and cmd.exe processes, indicating the parent-child relationship. Standard PowerShell telemetry shows only execution policy bypass commands in the PowerShell operational log.

## What This Dataset Does Not Contain

Notably absent are direct registry modification events. This appears to be because the current Sysmon configuration does not include RegistryEvent monitoring rules - there are no Sysmon EID 12, 13, or 14 events that would show the actual registry key creation or value setting. The Windows Security audit policy also has object access auditing disabled, so there are no corresponding registry audit events from the Security log.

The PowerShell script block logging contains only test framework boilerplate (Set-StrictMode calls) and doesn't capture the actual PowerShell commands that initiated the attack, likely because the test execution occurred through direct process invocation rather than interactive PowerShell scripting.

## Assessment

This dataset provides good coverage for detecting this technique through process-based monitoring. The command-line arguments captured in both Security 4688 and Sysmon EID 1 events contain the complete attack signature, including the specific registry path and the malicious payload (notepad.exe). The process chain is clearly visible and would be sufficient for building robust detections.

However, the dataset would be significantly stronger with registry monitoring enabled, as the actual registry modification is the core malicious action. Defense teams should note that relying solely on process execution monitoring for registry-based persistence techniques may miss attacks that use alternative registry modification methods (WMI, .NET Registry classes, etc.).

## Detection Opportunities Present in This Data

1. **Command-line detection for reg.exe targeting MyComputer cleanuppath** - Monitor for reg.exe executions with command lines containing "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\cleanuppath"

2. **Suspicious registry path keywords** - Alert on any process command lines referencing the cleanuppath registry location, which should be extremely rare in legitimate operations

3. **Process chain analysis** - Detect PowerShell spawning cmd.exe which then spawns reg.exe, particularly when targeting system registry locations

4. **REG_EXPAND_SZ data type targeting system executables** - Monitor for registry additions using REG_EXPAND_SZ type with values pointing to system32 executables or other suspicious paths

5. **PowerShell process access patterns** - Alert on PowerShell processes accessing newly created child processes with full access rights (0x1FFFFF), which may indicate programmatic process management for evasion
