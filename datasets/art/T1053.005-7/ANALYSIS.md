# T1053.005-7: Scheduled Task — Scheduled Task Executing Base64 Encoded Commands From Registry

## Technique Context

T1053.005 (Scheduled Task) is a fundamental persistence technique where adversaries create scheduled tasks to maintain access and execute code at predetermined intervals or system events. This specific test demonstrates a sophisticated variant that combines scheduled tasks with registry-based payload storage and base64 encoding for obfuscation. Attackers use this approach to hide malicious commands in the registry, making detection more challenging since the scheduled task itself appears to run legitimate PowerShell commands that dynamically retrieve and decode the actual payload. The detection community focuses on monitoring scheduled task creation, especially those with suspicious command lines containing PowerShell execution, base64 decoding functions, and registry access patterns.

## What This Dataset Contains

This dataset captures a complete scheduled task creation workflow with registry-based payload storage. The attack begins with PowerShell processes (PIDs 28488, 28592, 29240) executing the setup commands. Security event 4688 shows the critical command execution: `"cmd.exe" /c reg add HKCU\SOFTWARE\ATOMIC-T1053.005 /v test /t REG_SZ /d cGluZyAxMjcuMC4wLjE= /f & schtasks.exe /Create /F /TN "ATOMIC-T1053.005" /TR "cmd /c start /min \"\" powershell.exe -Command IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\\SOFTWARE\\ATOMIC-T1053.005).test)))" /sc daily /st 07:45`.

The technique involves two key components: first, `reg.exe` (PID 28204) writes the base64-encoded payload `cGluZyAxMjcuMC4wLjE=` (which decodes to "ping 127.0.0.1") to `HKCU\SOFTWARE\ATOMIC-T1053.005`. Second, `schtasks.exe` (PID 27752) creates a scheduled task that will execute PowerShell to retrieve this registry value, decode it from base64, and execute the result.

Sysmon provides comprehensive process creation events for the entire chain: PowerShell → cmd.exe → reg.exe and schtasks.exe. Registry modifications are captured in Sysmon event 13, showing the Task Scheduler service (svchost.exe PID 2316) writing to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\ATOMIC-T1053.005\` with values including the task ID `{901F5A07-557E-496C-B3E6-3A04290AA292}`. Task Scheduler operational events 106 and 140 confirm successful task registration and updates. Sysmon event 11 shows the task file creation at `C:\Windows\System32\Tasks\ATOMIC-T1053.005`.

## What This Dataset Does Not Contain

The dataset captures only the task creation phase, not the actual scheduled execution of the malicious payload. Since this is a one-time setup test, we don't see the task triggering at the scheduled time (07:45 daily), which would involve Task Scheduler launching cmd.exe and subsequently PowerShell to read from the registry and decode the base64 command. The base64 payload itself is benign (ping command), so no network activity or additional suspicious behavior occurs. The registry write containing the base64 payload is not captured in the Sysmon events, likely because the sysmon-modular configuration doesn't monitor all HKCU registry modifications, focusing instead on security-relevant registry locations.

## Assessment

This dataset provides excellent coverage for detecting the scheduled task creation aspect of this technique. The Security channel's command-line auditing captures the complete attack chain with full command-line arguments, including the sophisticated PowerShell payload that combines registry access, base64 decoding, and code execution. Sysmon's process creation events complement this with detailed process genealogy and the critical schtasks.exe execution with the suspicious task action. The registry events showing Task Scheduler's internal operations and the task file creation provide additional detection opportunities. However, for complete coverage of this technique, defenders would need to monitor the actual task execution when it triggers, which would require longer-term monitoring beyond this test's scope.

## Detection Opportunities Present in This Data

1. **Scheduled Task Creation with Suspicious PowerShell Commands** - Security 4688 and Sysmon 1 events showing schtasks.exe creating tasks with PowerShell command lines containing `IEX`, `FromBase64String`, and `Get-ItemProperty` functions

2. **Base64 Decoding in Scheduled Task Actions** - Command-line arguments in scheduled tasks containing `[System.Convert]::FromBase64String` or similar base64 decoding methods

3. **Registry-Based Payload Storage Pattern** - Sequence of reg.exe writing values followed immediately by schtasks.exe creation with registry read operations in the task action

4. **PowerShell Execution with Registry Access and Code Execution** - Task actions containing PowerShell commands that read from registry (`Get-ItemProperty`) and execute the result (`IEX`)

5. **Scheduled Task Creation with /F (Force) Flag** - Security events showing schtasks.exe with `/F` parameter, often used to overwrite existing tasks

6. **Task Scheduler Service Registry Modifications** - Sysmon 13 events from svchost.exe writing to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\` indicating new task registration

7. **Task File Creation in System32\Tasks** - Sysmon 11 events showing file creation in `C:\Windows\System32\Tasks\` with suspicious task names

8. **Command Chain Analysis** - Process tree showing PowerShell spawning cmd.exe, which spawns both reg.exe and schtasks.exe in sequence for coordinated registry and persistence setup
