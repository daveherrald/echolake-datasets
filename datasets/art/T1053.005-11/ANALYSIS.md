# T1053.005-11: Scheduled Task — Scheduled Task Persistence via CompMgmt.msc

## Technique Context

T1053.005 (Scheduled Task/Job: Scheduled Task) involves adversaries creating or modifying Windows scheduled tasks to establish persistence or execute malicious code. This technique is particularly valuable to attackers because scheduled tasks provide a legitimate Windows mechanism that can execute with elevated privileges, survive reboots, and blend in with normal system operations.

This specific test demonstrates a sophisticated persistence technique that combines scheduled task creation with COM hijacking. By modifying the registry association for .msc files (specifically targeting `HKEY_CURRENT_USER\Software\Classes\mscfile\shell\open\command`) and then creating a scheduled task that launches `compmgmt.msc`, an attacker can achieve code execution whenever the scheduled task triggers or when any .msc file is opened.

Detection engineers focus on monitoring `schtasks.exe` execution with creation parameters, registry modifications to COM/file handler associations, and the Task Scheduler operational logs for new task registration events. The combination of these activities within a short timeframe is particularly suspicious.

## What This Dataset Contains

This dataset captures a complete execution chain showing the technique in action. The attack begins with PowerShell execution, followed by a complex command line executed via cmd.exe:

`"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Classes\mscfile\shell\open\command" /ve /t REG_EXPAND_SZ /d "c:\windows\System32\calc.exe" /f & schtasks /Create /TN "CompMgmtBypass" /TR "compmgmt.msc" /SC ONLOGON /RL HIGHEST /F & ECHO Let's open the Computer Management console now... & compmgmt.msc`

Key process execution events include:
- Sysmon EID 1 captures the cmd.exe process creation with the full command line
- Sysmon EID 1 captures reg.exe execution: `reg add "HKEY_CURRENT_USER\Software\Classes\mscfile\shell\open\command" /ve /t REG_EXPAND_SZ /d "c:\windows\System32\calc.exe" /f`
- Sysmon EID 1 captures schtasks.exe execution: `schtasks /Create /TN "CompMgmtBypass" /TR "compmgmt.msc" /SC ONLOGON /RL HIGHEST /F`
- Security EID 4688 events provide comprehensive process creation coverage for all spawned processes

Registry modifications are captured through:
- Sysmon EID 13 shows the COM hijack: `HKU\.DEFAULT\Software\Classes\mscfile\shell\open\command\(Default)` set to `c:\windows\System32\calc.exe`
- Multiple Sysmon EID 13 events capture scheduled task registry entries under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CompMgmtBypass`

The Task Scheduler operational log provides definitive evidence:
- EID 106: Task registration for "CompMgmtBypass"
- EID 140: Task update for "CompMgmtBypass"

File system artifacts include Sysmon EID 11 showing creation of `C:\Windows\System32\Tasks\CompMgmtBypass`.

## What This Dataset Does Not Contain

The dataset lacks several important elements that would complete the attack picture. Most notably, there are no process creation events for calc.exe actually executing, which would demonstrate the COM hijack working when compmgmt.msc is launched. While mmc.exe (the MMC host for compmgmt.msc) is launched according to Security EID 4688, the expected calc.exe execution from the hijacked file association is absent.

PowerShell script block logging (EID 4104) contains only test framework boilerplate code rather than the actual technique implementation, limiting visibility into the PowerShell portion of the execution chain. Additionally, there are no network connections from the spawned processes, which might be expected in a real attack scenario where the persistence mechanism is used for command and control.

The Sysmon ProcessCreate events are filtered by the sysmon-modular configuration, so some intermediate processes in the execution chain may be missing from Sysmon logs, though Security 4688 events provide comprehensive coverage.

## Assessment

This dataset provides excellent visibility into the scheduled task creation and COM hijacking components of the technique. The combination of Sysmon process creation, registry modification events, Security audit logs, and Task Scheduler operational logs creates a comprehensive detection foundation. The command-line logging is particularly valuable, capturing the full attack chain in a single cmd.exe execution.

The registry modification telemetry is especially strong, clearly showing both the COM hijack setup and the scheduled task infrastructure creation. The Task Scheduler logs provide authoritative evidence of task creation that would be difficult for attackers to evade.

However, the dataset would be stronger with evidence of the persistence mechanism actually working (calc.exe execution) and more detailed PowerShell logging showing the technique implementation rather than just test framework code.

## Detection Opportunities Present in This Data

1. **Scheduled Task Creation with Suspicious Parameters** - Monitor Sysmon EID 1 for schtasks.exe execution with `/Create`, `/TN`, and `/RL HIGHEST` parameters, especially when combined with .msc file references in task actions.

2. **COM Hijacking via Registry Modification** - Alert on Sysmon EID 13 registry modifications to `*\Software\Classes\mscfile\shell\open\command\(Default)` or similar COM handler paths, particularly when the target is changed to executable files outside expected paths.

3. **Task Scheduler Operational Events** - Monitor Task Scheduler EID 106 (task registration) for new tasks with suspicious names or actions, especially those targeting .msc files or other administrative tools.

4. **Compound Command Execution** - Detect Security EID 4688 process creation events for cmd.exe with command lines containing multiple chained commands (`&` operators) that include both `reg add` and `schtasks` operations.

5. **Registry and Task File Creation Correlation** - Correlate Sysmon EID 13 registry modifications to COM handlers with Sysmon EID 11 file creation events in `C:\Windows\System32\Tasks\` within a short time window.

6. **Process Chain Analysis** - Monitor for PowerShell spawning cmd.exe which then spawns both reg.exe and schtasks.exe in sequence, indicating potential automated attack tool usage.

7. **MMC with Loaded .NET Runtime** - Alert on Sysmon EID 7 image loads of .NET runtime components (mscoreei.dll, clr.dll) into mmc.exe processes, which may indicate COM hijacking or malicious snap-in loading.
