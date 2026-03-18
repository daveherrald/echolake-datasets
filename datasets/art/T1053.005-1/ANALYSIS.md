# T1053.005-1: Scheduled Task — Scheduled Task Startup Script

## Technique Context

T1053.005 (Scheduled Task/Job: Scheduled Task) is a versatile technique attackers use for execution, persistence, and privilege escalation on Windows systems. Scheduled tasks provide a legitimate Windows mechanism to run programs at specific times, system events (startup, logon), or intervals. Attackers abuse this functionality to maintain persistence after system restarts, execute payloads with elevated privileges, or trigger malicious actions based on system events.

The detection community focuses heavily on monitoring scheduled task creation through multiple data sources: Security event logs (4698), Task Scheduler operational logs (106, 200, 201), Sysmon registry modifications (13), and file creation events (11) for task definition files. Key detection points include unusual task names, suspicious command lines in task actions, tasks configured to run as SYSTEM, and tasks triggered by system events like startup or logon.

## What This Dataset Contains

This dataset captures the complete lifecycle of scheduled task creation using the native `schtasks.exe` utility. The technique creates two scheduled tasks with different triggers:

**Process Chain Evidence:**
- PowerShell (PID 6420) executes: `"cmd.exe" /c schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe" & schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"`
- CMD (PID 6916) spawns two schtasks.exe processes (PIDs 2456, 4932)
- Security 4688 events capture the full command lines with task parameters

**Registry Modifications (Sysmon EID 13):**
Task cache registry entries under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`:
- `T1053_005_OnLogon\Id`: `{549A3EF1-F56F-493B-8158-31C1A9A389F6}`
- `T1053_005_OnLogon\Index`: `DWORD (0x00000002)`
- `T1053_005_OnStartup\Id`: `{45A68E7C-7AC1-4609-A90C-3852D347175A}` 
- `T1053_005_OnStartup\Index`: `DWORD (0x00000001)`

**File Creation Events (Sysmon EID 11):**
- `C:\Windows\System32\Tasks\T1053_005_OnLogon`
- `C:\Windows\System32\Tasks\T1053_005_OnStartup`

**Task Scheduler Operational Logs (EID 106):**
- Task "\T1053_005_OnLogon" registered by "ACME\ACME-WS02$"
- Task "\T1053_005_OnStartup" registered by "S-1-5-18"

**DLL Loading Evidence:**
Sysmon EID 7 captures `taskschd.dll` loading into both schtasks.exe processes, indicating Task Scheduler COM API usage.

## What This Dataset Does Not Contain

The dataset does not contain Security event 4698 (A scheduled task was created), which is a primary detection source that many organizations rely on. This could indicate the audit policy for "Audit Other Object Access Events" is not enabled, which is required for 4698 generation.

No task execution events are present since the created tasks are triggered by system events (logon/startup) that don't occur during this test execution. The dataset also doesn't show task deletion or modification events that would occur during cleanup phases.

The PowerShell logging primarily contains boilerplate Set-StrictMode and Set-ExecutionPolicy commands rather than the actual task creation PowerShell code, suggesting the technique uses direct command execution rather than PowerShell cmdlets.

## Assessment

This dataset provides excellent coverage for detecting scheduled task creation through multiple complementary data sources. The combination of process creation (Security 4688), registry modifications (Sysmon 13), file creation (Sysmon 11), and Task Scheduler operational logs (106) creates a robust detection foundation.

The process telemetry is particularly valuable, showing the complete command lines with task names, triggers, and actions. The registry events provide low-level evidence of task cache population, while file creation events show the physical task definition files. The Task Scheduler logs add authoritative confirmation of task registration.

Missing Security 4698 events represent a gap that many detection rules depend on, but the available telemetry sources provide sufficient alternative detection opportunities.

## Detection Opportunities Present in This Data

1. **Suspicious schtasks.exe command line patterns** - Security EID 4688 with command lines containing `/create`, `/tn`, and suspicious task names or actions

2. **Task Scheduler registry modifications** - Sysmon EID 13 events targeting `TaskCache\Tree\*` registry paths, especially with new task names

3. **Scheduled task file creation** - Sysmon EID 11 events creating files in `C:\Windows\System32\Tasks\` with suspicious names

4. **Task Scheduler operational logs** - EID 106 events showing new task registration, correlating task names with user contexts

5. **Process ancestry anomalies** - Unusual parent processes spawning schtasks.exe (PowerShell, cmd.exe from non-administrative contexts)

6. **Task definition command line analysis** - Parsing `/tr` parameter values for suspicious executables, LOLBins, or encoded commands

7. **Privilege escalation indicators** - Tasks created with `/ru system` parameter or other high-privilege accounts

8. **Persistence trigger detection** - Tasks configured with `/sc onstart`, `/sc onlogon`, or other boot/logon persistence triggers
