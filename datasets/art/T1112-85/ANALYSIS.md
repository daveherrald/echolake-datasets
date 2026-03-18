# T1112-85: Modify Registry — Abusing Windows TelemetryController Registry Key for Persistence

## Technique Context

T1112: Modify Registry is a fundamental technique where adversaries alter Windows registry entries to establish persistence, escalate privileges, or evade defenses. This specific test (T1112-85) demonstrates abuse of the Windows TelemetryController registry mechanism for persistence. The TelemetryController framework allows processes to register commands that will be executed by the Windows compatibility system, providing a relatively obscure persistence mechanism that many defenders may overlook.

Attackers value registry-based persistence because it survives reboots and often blends with legitimate system activity. The TelemetryController path (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController`) is particularly attractive because it's less monitored than common persistence locations like Run keys or services. Detection engineering typically focuses on registry modifications to well-known persistence locations, command-line patterns indicating registry manipulation, and process ancestry chains involving registry tools.

## What This Dataset Contains

This dataset captures a successful registry persistence technique using the TelemetryController mechanism. The attack chain begins with PowerShell execution and uses the `reg.exe` utility to create the malicious registry entry.

The core technique evidence appears in Security event 4688, which shows the command execution: `"cmd.exe" /c reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController\NewKey" /t REG_SZ /v Command /d C:\Windows\System32\notepad.exe /f`. This creates a registry value named "Command" containing the path to notepad.exe under a new subkey in the TelemetryController path.

The process chain is: `powershell.exe` → `cmd.exe` → `reg.exe`. Sysmon captures this with EID 1 events showing the process creations, including the reg.exe execution with the full command line: `reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController\NewKey" /t REG_SZ /v Command /d C:\Windows\System32\notepad.exe /f`.

Sysmon EID 10 events show PowerShell accessing both the spawned cmd.exe and whoami.exe processes with full access rights (0x1FFFFF), indicating the parent process maintaining control over its children. A whoami.exe execution precedes the registry modification, likely for reconnaissance.

## What This Dataset Does Not Contain

This dataset lacks the actual registry modification events. There are no Sysmon EID 13 (Registry value set) or EID 12 (Registry object create/delete) events, indicating the sysmon-modular configuration doesn't capture registry operations or these specific registry paths aren't monitored. This is a significant gap since the registry modification is the technique's core objective.

The dataset also doesn't show the persistence mechanism being triggered - there's no evidence of the TelemetryController framework later executing notepad.exe, which would demonstrate the technique's success. The technique creates persistence but doesn't activate it during this test execution.

PowerShell script block logging (EID 4104) contains only error handling boilerplate from the test framework rather than the actual commands that initiated the technique.

## Assessment

This dataset provides partial but valuable evidence for detecting this technique. While missing the registry modification telemetry itself, it captures the attack's execution phase with high-quality process creation and command-line data. The Security channel events with full command-line auditing prove most valuable, clearly showing the suspicious reg.exe command targeting the TelemetryController path.

The process ancestry chain (PowerShell → cmd.exe → reg.exe) with specific command-line arguments provides strong detection opportunities. For organizations with registry monitoring capabilities, this data would be complemented by registry modification events, but the process-level telemetry alone enables effective detection.

The dataset would be stronger with registry monitoring enabled to capture the actual persistence mechanism creation and ideally demonstration of the persistence trigger.

## Detection Opportunities Present in This Data

1. **TelemetryController Registry Path Targeting** - Monitor Security EID 4688 for reg.exe command lines containing "AppCompatFlags\TelemetryController" to detect this specific persistence technique.

2. **Registry Tool Execution from PowerShell** - Detect reg.exe spawned from powershell.exe as shown in the process creation events, particularly when modifying HKLM registry locations.

3. **Suspicious Command Structure** - Alert on command lines matching the pattern `reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController\*" /v Command /d *` which indicates potential TelemetryController abuse.

4. **Process Access to Registry Tools** - Monitor Sysmon EID 10 for PowerShell processes accessing reg.exe or cmd.exe with full access rights, indicating potential process injection or control.

5. **PowerShell Spawning System Tools** - Detect PowerShell parent processes creating cmd.exe children that subsequently launch reg.exe, indicating potential living-off-the-land technique usage.

6. **Registry Modification Command Patterns** - Look for reg.exe executions with the `/t REG_SZ /v Command /d` parameter combination, which is characteristic of setting executable paths in registry persistence mechanisms.
