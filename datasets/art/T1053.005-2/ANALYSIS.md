# T1053.005-2: Scheduled Task — Scheduled task Local

## Technique Context

T1053.005 (Scheduled Task) represents one of the most common persistence and execution mechanisms available to attackers on Windows systems. Adversaries leverage the Windows Task Scheduler to maintain persistence across reboots, execute code at specific times, or run with elevated privileges. This technique is particularly valuable because scheduled tasks can execute with SYSTEM privileges and persist through system restarts. Detection engineers focus on monitoring task creation events, command-line patterns in task definitions, and unusual executables or scripts being scheduled. The technique spans multiple tactics (execution, persistence, privilege escalation) because tasks can immediately execute payloads, maintain access across sessions, and run with higher privileges than the creating process.

## What This Dataset Contains

This dataset captures a successful scheduled task creation using the `schtasks.exe` utility. The attack chain begins with PowerShell (PID 21704) spawning cmd.exe (PID 20364) with the command line `"cmd.exe" /c SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10`. The cmd.exe process then executes schtasks.exe (PID 20548) with the full command `SCHTASKS  /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10`. 

The dataset contains rich telemetry across multiple channels:
- **Security channel**: Process creation events (4688) showing the full command line and process chain: powershell.exe → cmd.exe → schtasks.exe
- **Sysmon channel**: Process creation events (EID 1) with detailed hashes and parent-child relationships, plus image loading events (EID 7) showing taskschd.dll being loaded by schtasks.exe
- **Task Scheduler channel**: Registration event (EID 106) confirming task creation: `User "ACME\ACME-WS02$"  registered Task Scheduler task "\spawn"`
- **Registry activity**: Sysmon EID 13 events capturing registry writes to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\spawn\` including Index, Id, and SD (Security Descriptor) values
- **File system activity**: Sysmon EID 11 showing creation of the task definition file at `C:\Windows\System32\Tasks\spawn`

## What This Dataset Does Not Contain

The dataset does not capture the actual execution of the scheduled task, as the start time was set to 20:10 (8:10 PM) but the test executed during the afternoon. No task execution events are present, which would normally include additional process creation events when the task fires. The PowerShell channel contains only test framework boilerplate (`Set-ExecutionPolicy` and `Set-StrictMode` scriptblocks) without the actual task creation PowerShell commands, indicating the technique was executed through direct command-line invocation rather than PowerShell cmdlets like `Register-ScheduledTask`. The dataset also lacks any WinEvent-Application logs that might contain additional Task Scheduler operational details.

## Assessment

This dataset provides excellent coverage for detecting scheduled task creation through command-line utilities. The combination of Security 4688 events with full command lines, Sysmon process creation with detailed metadata, registry modifications, file system changes, and native Task Scheduler logs creates multiple detection opportunities. The presence of taskschd.dll loading events adds another detection vector. However, the dataset would be stronger if it included actual task execution, which would demonstrate the full attack lifecycle and provide additional telemetry for detecting malicious task behavior during runtime.

## Detection Opportunities Present in This Data

1. **Command-line analysis of schtasks.exe execution** - Security EID 4688 and Sysmon EID 1 capture the full schtasks command line with suspicious parameters like `/Create`, `/SC ONCE`, and executable paths that could indicate malicious task registration

2. **Process chain analysis for task scheduler abuse** - Multiple events show the progression from powershell.exe → cmd.exe → schtasks.exe, a pattern commonly associated with scripted task creation and potential automation

3. **Registry monitoring for task cache modifications** - Sysmon EID 13 events capture writes to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\spawn\` which can detect task registration even when command-line logging is unavailable

4. **File creation monitoring in Tasks directory** - Sysmon EID 11 shows creation of `C:\Windows\System32\Tasks\spawn`, providing filesystem-based detection of new scheduled tasks

5. **Task Scheduler operational log analysis** - EID 106 from Microsoft-Windows-TaskScheduler/Operational provides native confirmation of task registration with user context

6. **DLL loading pattern analysis** - Sysmon EID 7 captures taskschd.dll being loaded by schtasks.exe, which could help identify processes interacting with Task Scheduler APIs

7. **Privilege escalation detection through task scheduling** - Security EID 4703 shows token rights adjustment for the PowerShell process, combined with task creation could indicate attempts to schedule privileged execution

8. **Anomalous parent-child process relationships** - The specific pattern of PowerShell spawning cmd.exe to execute schtasks.exe may indicate scripted or automated task creation rather than legitimate administrative activity
