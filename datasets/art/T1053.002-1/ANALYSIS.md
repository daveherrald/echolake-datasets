# T1053.002-1: At — At.exe Scheduled task

## Technique Context

T1053.002 represents the use of the legacy Windows `at.exe` utility to create scheduled tasks for persistence, privilege escalation, or execution. While Microsoft deprecated `at.exe` in favor of `schtasks.exe`, it remains available on modern Windows systems and continues to be used by attackers for its simplicity and lower profile compared to more monitored scheduling mechanisms. The technique creates tasks that execute under the SYSTEM context, making it particularly attractive for privilege escalation scenarios. Detection engineers focus on monitoring `at.exe` execution, named pipe connections to the `\atsvc` pipe, and the creation of legacy scheduled tasks in the Windows Task Scheduler service.

## What This Dataset Contains

This dataset captures a successful execution of the `at.exe` utility to schedule a task. The key evidence includes:

**Process Creation Chain**: Security event 4688 shows the process chain: `powershell.exe` → `cmd.exe` → `at.exe` with the command line `"cmd.exe" /c at 13:20 /interactive cmd` followed by `at 13:20 /interactive cmd`. Sysmon event 1 provides additional detail with process GUIDs and hashes for both the cmd.exe execution (`{9dc7570a-5036-69b4-3726-000000001000}`) and the at.exe execution (`{9dc7570a-5036-69b4-3926-000000001000}`).

**Named Pipe Communication**: Sysmon event 18 captures the critical pipe connection to `\atsvc` by the at.exe process (PID 19432), which represents the communication channel to the Windows Task Scheduler service for creating the scheduled task.

**Process Context**: All processes execute under `NT AUTHORITY\SYSTEM` with System integrity level, demonstrating the high-privilege context typical of this technique.

**Exit Codes**: Security events 4689 show the at.exe process exited with status `0x1`, indicating the command completed but potentially with an error condition.

## What This Dataset Does Not Contain

The dataset lacks several key elements for comprehensive coverage of this technique:

**Task Scheduler Service Logs**: No events from the Microsoft-Windows-TaskScheduler/Operational channel are present, which would show the actual scheduled task creation, task registration, or execution attempts.

**Registry Modifications**: Missing registry events that would capture the scheduled task storage in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` or legacy AT service locations.

**Sysmon ProcessCreate Filtering**: The cmd.exe parent process and several PowerShell-related processes are captured because they match the sysmon-modular include patterns for suspicious processes, but we may be missing other spawned processes that don't match these patterns.

**Task Execution Evidence**: No evidence of the scheduled task actually executing at the specified time (13:20), which would require waiting for the scheduled execution time.

## Assessment

The dataset provides solid evidence for detecting at.exe usage through process creation monitoring and named pipe analysis. The Security 4688 events with command-line logging offer reliable detection opportunities, while the Sysmon data adds valuable context with process relationships and the critical `\atsvc` pipe connection. However, the dataset's detection value is somewhat limited by the absence of Task Scheduler service logs and registry modifications. The process exit code of `0x1` suggests the scheduled task creation may not have been entirely successful, which could explain the missing task registration evidence. For building comprehensive detections of T1053.002, this data provides good coverage of the execution phase but would benefit from Task Scheduler operational logs to capture the persistence mechanism completion.

## Detection Opportunities Present in This Data

1. **At.exe Process Execution**: Monitor Security 4688 or Sysmon 1 events for `C:\Windows\System32\at.exe` process creation with any command-line arguments, as legitimate use of at.exe is extremely rare in modern environments.

2. **At.exe Command Line Patterns**: Detect at.exe executions with time specifications and `/interactive` flags through command-line analysis in process creation events (`at <time> /interactive <command>`).

3. **Named Pipe Connection to \atsvc**: Monitor Sysmon 18 events for connections to the `\atsvc` named pipe, which is the primary communication channel for the legacy AT service and indicates scheduled task manipulation.

4. **Process Chain Analysis**: Correlate cmd.exe spawning at.exe processes, particularly when cmd.exe itself was spawned by scripting engines like powershell.exe, indicating potential automated task scheduling.

5. **High-Privilege At.exe Execution**: Alert on at.exe processes running under SYSTEM or other high-privilege contexts, as this indicates potential privilege escalation or lateral movement attempts.

6. **At.exe Parent Process Context**: Monitor for at.exe spawned by unusual parent processes beyond typical administrative tools, particularly when spawned by LOLBins or scripting engines.
