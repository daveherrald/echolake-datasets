# T1053.005-3: Scheduled Task — Scheduled task Remote

## Technique Context

T1053.005 Scheduled Task/Job - Scheduled Task is a fundamental persistence and execution technique where attackers create scheduled tasks to maintain access or execute malicious code at specific times or system events. This technique is particularly valuable for adversaries because scheduled tasks run with elevated privileges when configured appropriately and provide a legitimate mechanism that blends with normal system operations.

The detection community focuses heavily on monitoring schtasks.exe command-line parameters, tracking scheduled task creation events, and identifying suspicious task configurations—especially those with unusual execution times, non-standard executables, or tasks created remotely. The "remote" aspect of this test (creating tasks on localhost) simulates lateral movement scenarios where attackers create scheduled tasks on remote systems they've compromised.

## What This Dataset Contains

This dataset captures a failed attempt to create a remote scheduled task using schtasks.exe. The key evidence includes:

**Process execution chain**: PowerShell → cmd.exe → schtasks.exe, visible in both Security 4688 events and Sysmon EID 1 events. The schtasks.exe process (PID 22792) was spawned with the command line `SCHTASKS /Create /S localhost /RU DOMAIN\user /RP At0micStrong /TN "Atomic task" /TR "C:\windows\system32\cmd.exe" /SC daily /ST 20:10`.

**Failed execution indicators**: The schtasks.exe process exits with status code 0x1 (visible in Security EID 4689), indicating the task creation failed. The parent cmd.exe process also exits with status 0x1, confirming the failure propagated up the process chain.

**Task Scheduler DLL loading**: Sysmon EID 7 shows schtasks.exe loading `C:\Windows\System32\taskschd.dll`, the Task Scheduler COM API, demonstrating the attempt to interact with the Windows Task Scheduler service.

**Credential specification**: The command line reveals an attempt to create a task running under `DOMAIN\user` with password `At0micStrong`, targeting localhost (simulating remote task creation).

## What This Dataset Does Not Contain

The dataset lacks the most critical evidence for successful scheduled task detection: **no Task Scheduler event log entries** (Microsoft-Windows-TaskScheduler/Operational channel events like EID 106, 129, or 141) that would indicate successful task registration. This absence, combined with the exit code 0x1, confirms the technique failed.

There are **no registry modifications** in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` that would occur with successful task creation. The Task Scheduler service likely rejected the task creation due to the invalid domain credential (`DOMAIN\user` doesn't exist in the acme.local domain).

The dataset also doesn't contain **network authentication events** that would occur with legitimate remote task scheduling, since the target was localhost.

## Assessment

This dataset provides moderate value for detection engineering, primarily as a negative case study. While it demonstrates the process execution patterns and command-line signatures that detections should monitor, the failed execution means it lacks the complete attack lifecycle telemetry that would validate detection coverage for successful scheduled task creation.

The Security 4688 events with full command-line logging provide excellent visibility into the schtasks.exe invocation patterns. The Sysmon process creation and image loading events add valuable context about the execution environment and task scheduler API usage. However, the absence of Task Scheduler operational logs limits its utility for validating detections that rely on those higher-fidelity data sources.

## Detection Opportunities Present in This Data

1. **Schtasks.exe process monitoring** - Security EID 4688 and Sysmon EID 1 both capture the schtasks.exe execution with suspicious parameters including `/RU` (run as user), `/RP` (password), and `/S localhost` (remote specification)

2. **Command-line pattern detection** - The full command line `SCHTASKS /Create /S localhost /RU DOMAIN\user /RP At0micStrong /TN "Atomic task"` contains multiple suspicious indicators including hardcoded credentials and generic task names

3. **Process tree analysis** - The PowerShell → cmd.exe → schtasks.exe execution chain visible in parent process relationships indicates potential scripted task creation

4. **Task Scheduler API usage** - Sysmon EID 7 shows taskschd.dll loading, which could be monitored to detect programmatic task scheduler interactions

5. **Failed execution correlation** - The exit code 0x1 from both schtasks.exe and cmd.exe processes can be correlated to identify failed scheduled task creation attempts, potentially indicating reconnaissance or credential issues

6. **Credential exposure detection** - The cleartext password `At0micStrong` in the command line demonstrates the value of monitoring schtasks.exe command lines for embedded credentials
