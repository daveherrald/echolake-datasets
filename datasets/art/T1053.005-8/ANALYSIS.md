# T1053.005-8: Scheduled Task — Import XML Schedule Task with Hidden Attribute

## Technique Context

T1053.005 (Scheduled Task) is a fundamental persistence technique where attackers create scheduled tasks to maintain presence on compromised systems. This specific test demonstrates importing a pre-crafted XML task definition with the hidden attribute set, making the task invisible in standard Task Scheduler GUI views. Attackers commonly use this approach to persist malware execution, run reconnaissance commands, or establish backdoors while evading casual inspection. The hidden attribute is particularly valuable for defense evasion, as it prevents the task from appearing in the main Task Scheduler interface that administrators typically check. Detection engineers focus on monitoring task creation APIs (both schtasks.exe usage and direct WMI/CIM calls), registry modifications under the TaskCache registry keys, and file system changes in the Tasks directory.

## What This Dataset Contains

The dataset captures a PowerShell-based scheduled task creation using WMI/CIM methods. Security event 4688 shows the main PowerShell execution with the full command line: `"powershell.exe" & {$xml = [System.IO.File]::ReadAllText(\"C:\AtomicRedTeam\atomics\T1053.005\src\T1053_05_SCTASK_HIDDEN_ATTRIB.xml\")` followed by `Invoke-CimMethod -ClassName PS_ScheduledTask -NameSpace \"Root\Microsoft\Windows\TaskScheduler\" -MethodName \"RegisterByXml\"`. 

Sysmon captures the actual task registration through registry modifications (Event ID 13) under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\atomic red team\` with entries for SD (security descriptor), Index (DWORD 0x00000002), and Id ({C0824717-46FA-46F6-ABDA-2667D574E165}). File creation events (Sysmon Event ID 11) show the task file being written to `C:\Windows\System32\Tasks\atomic red team` by svchost.exe (PID 2316), indicating the Task Scheduler service processed the registration.

TaskScheduler operational logs capture both the initial registration (Event ID 106) and subsequent update (Event ID 140) for task "\atomic red team" by user "ACME\ACME-WS02$". PowerShell script block logging shows the actual technique execution with the Invoke-CimMethod call and XML file reading operations.

## What This Dataset Does Not Contain

The dataset lacks the actual XML task definition file contents that would reveal the hidden attribute configuration and task payload details. No Sysmon ProcessCreate events are captured for schtasks.exe because the technique uses WMI/CIM methods instead of the command-line utility, and the sysmon-modular config's include-mode filtering doesn't capture the child PowerShell process creation. The dataset also missing any task execution events since this test only demonstrates task creation, not execution. There are no network connections or additional payload deployment activities that might occur in real-world scenarios where the hidden task would execute malicious code.

## Assessment

This dataset provides excellent telemetry for detecting WMI/CIM-based scheduled task creation. The combination of Security 4688 command-line logging, Sysmon registry monitoring, Task Scheduler operational logs, and PowerShell script block logging creates a comprehensive detection surface. The registry modifications and task file creation events provide high-fidelity indicators that are difficult for attackers to suppress. The TaskScheduler channel events offer domain-specific context that security teams often overlook but provide valuable persistence detection capabilities. The data quality is strong for building detections around non-schtasks.exe task creation methods, which are increasingly common in modern attacks.

## Detection Opportunities Present in This Data

1. **WMI/CIM Task Registration**: Monitor Security 4688 events for PowerShell processes using "Invoke-CimMethod" with "PS_ScheduledTask" class and "RegisterByXml" method names in command lines

2. **Task Registry Modifications**: Alert on Sysmon Event ID 13 registry writes to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` paths, especially when performed by PowerShell processes

3. **Task File Creation**: Monitor Sysmon Event ID 11 for file writes under `C:\Windows\System32\Tasks\` by svchost.exe processes, correlating with recent PowerShell task registration activity

4. **TaskScheduler Event Correlation**: Detect TaskScheduler Event IDs 106/140 for task registration/updates, especially when combined with PowerShell script block events containing "RegisterByXml"

5. **PowerShell Task Creation**: Hunt for PowerShell script blocks (Event ID 4104) containing "System.IO.File]::ReadAllText" combined with "Invoke-CimMethod" and "PS_ScheduledTask" strings indicating XML-based task import

6. **Suspicious Task Names**: Flag TaskScheduler events for tasks with generic names like "atomic red team" or other non-standard naming patterns that don't match legitimate administrative tasks
