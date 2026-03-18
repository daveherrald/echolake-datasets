# T1053.005-12: Scheduled Task — Scheduled Task Persistence via Eventviewer.msc

## Technique Context

T1053.005 represents the use of Windows Task Scheduler for persistence, execution, and privilege escalation. This specific test demonstrates a sophisticated UAC bypass technique that combines scheduled task creation with COM hijacking through registry modification. The attack leverages the fact that Event Viewer (eventvwr.msc) runs with elevated privileges and can be hijacked through the mscfile registry key to execute arbitrary code with elevated permissions. This technique is particularly valuable to attackers because it can bypass UAC without user interaction while establishing persistent execution through the Task Scheduler. Detection teams typically focus on monitoring scheduled task creation, registry modifications to COM handler keys, and the execution of administrative tools like eventvwr.msc from unusual contexts.

## What This Dataset Contains

This dataset captures a multi-stage attack that successfully creates a scheduled task with UAC bypass capabilities. The attack begins with PowerShell execution, followed by a cmd.exe command that performs three key actions in sequence: registry modification, scheduled task creation, and task execution.

The Security channel shows the complete process execution chain: `powershell.exe → cmd.exe → reg.exe` and `powershell.exe → cmd.exe → schtasks.exe` (twice). The critical cmd.exe command line reveals the full attack: `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Classes\mscfile\shell\open\command" /ve /t REG_EXPAND_SZ /d "c:\windows\System32\calc.exe" /f & schtasks /Create /TN "EventViewerBypass" /TR "eventvwr.msc" /SC ONLOGON /RL HIGHEST /F & ECHO Let's run the schedule task ... & schtasks /Run /TN "EventViewerBypass"`.

Sysmon captures the registry hijacking through EID 13: the reg.exe process writes to `HKU\.DEFAULT\Software\Classes\mscfile\shell\open\command\(Default)` with the value `c:\windows\System32\calc.exe`, establishing the COM hijack. Multiple Sysmon EID 13 events show the Task Scheduler service (svchost.exe) creating registry entries in the TaskCache for the "EventViewerBypass" task, including the task ID `{F3B32163-7884-4352-88A5-E2A8F168D6C6}`.

The TaskScheduler channel provides definitive evidence with EID 106 (task registration), EID 140 (task update), EID 110 (task launch), and notably EID 332 indicating the task failed to launch because no user was logged on, which is expected behavior for an ONLOGON trigger in this test environment.

Sysmon EID 11 shows the creation of the task definition file at `C:\Windows\System32\Tasks\EventViewerBypass`. The schtasks.exe processes are captured with complete command lines showing both task creation (`/Create /TN "EventViewerBypass" /TR "eventvwr.msc" /SC ONLOGON /RL HIGHEST /F`) and execution attempts (`/Run /TN "EventViewerBypass"`).

## What This Dataset Does Not Contain

The dataset does not contain evidence of the UAC bypass actually succeeding with payload execution. While the scheduled task is created and the registry hijack is established, there are no Sysmon ProcessCreate events for eventvwr.msc or calc.exe, indicating the bypass payload never executed. This is likely because the test runs as SYSTEM in a non-interactive session where the ONLOGON trigger condition cannot be satisfied.

The dataset lacks any network activity, file system artifacts beyond the task definition file, or evidence of the hijacked Event Viewer process tree that would demonstrate successful UAC bypass. There are no Sysmon ProcessCreate events filtered by the sysmon-modular configuration for eventvwr.msc, which is expected since Event Viewer is not typically considered a "suspicious" binary for inclusion filtering. Additionally, there are no Windows Defender alerts or blocks, suggesting this technique was not detected or prevented by the endpoint protection solution.

## Assessment

This dataset provides excellent telemetry for detecting the setup phase of this UAC bypass technique but limited insight into the execution phase. The combination of Security 4688 events with command-line logging, Sysmon registry monitoring (EID 13), and TaskScheduler operational events creates a comprehensive detection foundation. The registry modification to the mscfile COM handler is clearly visible, as is the scheduled task creation with suspicious characteristics (HIGHEST privilege level, eventvwr.msc as the task action).

The main limitation is the lack of successful UAC bypass execution, which reduces the dataset's utility for understanding the full attack lifecycle and developing detections for the post-bypass behavior. However, this limitation doesn't significantly impact the detection value since the setup activities themselves represent malicious behavior worthy of alerting.

## Detection Opportunities Present in This Data

1. **COM Hijack Registry Modification**: Monitor Sysmon EID 13 for writes to registry paths matching `*\Software\Classes\mscfile\shell\open\command*`, especially when the process is reg.exe or regedit.exe and the value points to non-standard executables.

2. **Suspicious Scheduled Task Creation**: Alert on Security EID 4688 for schtasks.exe with command lines containing `/Create` combined with `/RL HIGHEST` and task actions of `eventvwr.msc` or other administrative MMC snap-ins.

3. **Task Scheduler Service Registry Activity**: Detect Sysmon EID 13 events from svchost.exe writing to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` when preceded by suspicious schtasks.exe execution within a short time window.

4. **Multi-Stage Command Execution**: Build process chain analytics to detect cmd.exe executing sequences of reg.exe and schtasks.exe with UAC bypass-related parameters, especially when the parent process is PowerShell.

5. **TaskScheduler Operational Events**: Monitor TaskScheduler EID 106 for task registration events with task names suggesting bypass techniques or containing administrative tool references like "EventViewer", "MMC", or "UAC".

6. **High-Privilege Task Registration**: Alert on TaskScheduler EID 106 events where the task definition includes `HIGHEST` run level combined with administrative executable task actions.

7. **File System Artifacts**: Monitor Sysmon EID 11 for file creation in `C:\Windows\System32\Tasks\*` with names matching common UAC bypass patterns or containing administrative tool references.
