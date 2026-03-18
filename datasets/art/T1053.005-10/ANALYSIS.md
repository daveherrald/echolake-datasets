# T1053.005-10: Scheduled Task — Scheduled Task ("Ghost Task") via Registry Key Manipulation

## Technique Context

T1053.005 (Scheduled Task/Job: Scheduled Task) is a persistence and execution technique where adversaries create scheduled tasks to maintain access and execute code on compromised systems. The "Ghost Task" variant specifically refers to creating scheduled tasks through direct registry manipulation rather than using official Windows APIs like `schtasks.exe` or Task Scheduler COM objects. This approach attempts to bypass security tools that monitor standard task creation methods by writing directly to the `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` registry hive.

Ghost tasks are particularly interesting to detection engineers because they represent a more evasive approach to scheduled task persistence. Traditional scheduled task creation generates clear telemetry through standard Windows event logs (Security 4698, Task Scheduler 106/141), but registry-based creation may only leave traces in registry modification events and process creation logs when the task eventually executes.

## What This Dataset Contains

This dataset captures a failed attempt to create a ghost task using the GhostTask.exe tool. The key evidence appears in the Security event logs:

The technique execution shows a command line in Security EID 4688: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\PsExec.exe" \\localhost -accepteula -s "cmd.exe" & "C:\AtomicRedTeam\atomics\..\ExternalPayloads\GhostTask.exe" \\localhost add lilghostie "cmd.exe" "/c notepad.exe" $env:USERDOMAIN + '\' + $env:USERNAME logon`

However, the cmd.exe process (PID 32904) exits with status code 0x1 according to Security EID 4689, indicating the command failed. This suggests Windows Defender or another security control blocked the GhostTask.exe execution.

The dataset contains legitimate process activity with Sysmon EID 1 events for both `whoami.exe` and `cmd.exe` processes spawned by PowerShell, along with corresponding Security 4688 process creation events. Sysmon EID 10 (Process Access) events show PowerShell accessing both child processes with full access rights (0x1FFFFF).

PowerShell script block logging (EID 4104) only shows the typical test framework boilerplate with Set-StrictMode commands and one Set-ExecutionPolicy bypass command, with no actual ghost task creation code visible.

## What This Dataset Does Not Contain

The dataset is missing the most critical evidence for this technique:
- No registry modification events (Sysmon EID 12/13/14) showing writes to the TaskCache registry keys
- No Task Scheduler event logs (Microsoft-Windows-TaskScheduler/Operational) that would show task registration or execution
- No Security EID 4698 (scheduled task created) events
- No file system evidence of the GhostTask.exe tool execution or its registry manipulation attempts
- No evidence of the actual scheduled task ("lilghostie") being created or executing

The PowerShell script block logs don't contain the actual ghost task creation logic, suggesting the technique implementation was handled by the external GhostTask.exe binary rather than PowerShell commands. The failure of the cmd.exe process indicates Windows Defender likely blocked the technique before it could manipulate the registry.

## Assessment

This dataset provides limited value for understanding ghost task creation techniques. While it shows the attempt to execute the GhostTask.exe tool, the security control intervention means we don't see the actual registry manipulation that defines this technique. The most useful aspect is the command line reconstruction showing the intended ghost task parameters: task name "lilghostie", command "cmd.exe /c notepad.exe", and logon trigger type.

For detection engineering, this dataset better demonstrates security control efficacy than technique execution. The process creation telemetry is complete, but without registry events or successful task creation, it doesn't help analysts understand the technique's true footprint or develop registry-based detections.

## Detection Opportunities Present in This Data

1. **Suspicious process command lines** - The Security 4688 event contains the full GhostTask.exe command line with parameters that clearly indicate scheduled task manipulation attempts

2. **Unknown executable paths** - Process creation of tools from `\ExternalPayloads\` directories, particularly with names like "GhostTask.exe" that suggest evasive functionality

3. **PsExec lateral movement patterns** - The command line shows PsExec usage with localhost target, which is unusual for legitimate administration

4. **Process exit code analysis** - The cmd.exe exit status 0x1 indicates failure, which combined with the suspicious command line suggests blocked execution

5. **PowerShell privilege escalation** - Security EID 4703 shows PowerShell acquiring extensive privileges including SeBackupPrivilege and SeRestorePrivilege, which are commonly used for registry manipulation

6. **Parent-child process relationships** - Sysmon EID 1 events show the process chain from PowerShell → cmd.exe → intended GhostTask.exe execution
