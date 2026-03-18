# T1053.005-6: Scheduled Task — WMI Invoke-CimMethod Scheduled Task

## Technique Context

T1053.005 (Scheduled Task/Job: Scheduled Task) is a fundamental persistence and execution technique where attackers create Windows scheduled tasks to execute malicious payloads at specified times or system events. This technique provides attackers with a legitimate Windows mechanism for maintaining persistence while blending into normal administrative activities. The detection community focuses heavily on scheduled task creation through various interfaces — the traditional `schtasks.exe` command-line utility, COM objects via PowerShell, and WMI/CIM methods as demonstrated in this test.

This specific test demonstrates task creation through PowerShell's `Invoke-CimMethod` cmdlet against the `PS_ScheduledTask` WMI class, which represents a more modern approach compared to legacy `at.exe` or `schtasks.exe` commands. Attackers favor this method because it leverages native Windows management interfaces and can be executed entirely in memory through PowerShell, making it attractive for fileless attacks and living-off-the-land techniques.

## What This Dataset Contains

This dataset captures a successful scheduled task creation via WMI using PowerShell's CIM cmdlets. The key evidence includes:

**Primary PowerShell execution:** Security 4688 shows the PowerShell command line: `"powershell.exe" & {$xml = [System.IO.File]::ReadAllText(\"C:\AtomicRedTeam\atomics\T1053.005\src\T1053_005_WMI.xml\") Invoke-CimMethod -ClassName PS_ScheduledTask -NameSpace \"Root\Microsoft\Windows\TaskScheduler\" -MethodName \"RegisterByXml\" -Arguments @{ Force = $true; Xml =$xml; }}`

**Task registration evidence:** The Task Scheduler operational log contains two critical events — EID 106 (task registered) and EID 140 (task updated) both showing task name `\T1053_005_WMI` registered by `ACME\ACME-WS02$`.

**Registry artifacts:** Sysmon EID 13 events show the Task Scheduler service (svchost.exe PID 2316) writing registry values to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\T1053_005_WMI\` including the task ID `{F9B53A1F-D065-4169-8319-C9CD6CE6685D}`.

**File system evidence:** Sysmon EID 11 captures the creation of `C:\Windows\System32\Tasks\T1053_005_WMI` by the Task Scheduler service, representing the XML task definition file.

**PowerShell script block logging:** EID 4104 captures the actual script execution including the XML file read and `Invoke-CimMethod` call, providing complete visibility into the WMI-based task creation method.

## What This Dataset Does Not Contain

This dataset lacks several elements that would provide a complete picture of scheduled task abuse:

**Task execution telemetry:** The created task does not execute during the capture window, so we miss the actual payload execution that would be triggered by the task scheduler.

**XML task definition content:** While we see the task file creation, the actual XML content specifying the task's trigger, action, and security context is not captured in the logs.

**WMI query telemetry:** Despite the technique using WMI/CIM methods, we don't see corresponding WMI operational log entries that would show the specific WMI namespace and method invocations.

**Task Scheduler service logs beyond registration:** Additional task scheduler operational events that might show task validation, security checks, or scheduling details are not present.

## Assessment

This dataset provides excellent coverage for detecting WMI-based scheduled task creation through multiple high-fidelity data sources. The combination of command-line auditing, PowerShell script block logging, registry monitoring, file system monitoring, and Task Scheduler operational logs creates comprehensive detection opportunities with minimal false positive potential.

The Security 4688 events with command-line logging provide immediate detection value, while the PowerShell script block logs offer detailed visibility into the technique implementation. The registry and file system artifacts from Sysmon provide additional forensic context, and the Task Scheduler logs deliver authoritative evidence of task registration.

The primary limitation is the lack of task execution evidence, but this is expected since the test focuses solely on task creation. For production detection engineering, this dataset demonstrates how multiple telemetry sources can provide layered detection capabilities for this common persistence technique.

## Detection Opportunities Present in This Data

1. **PowerShell CIM method invocation detection** - Monitor PowerShell script blocks (EID 4104) for `Invoke-CimMethod` calls targeting `PS_ScheduledTask` class in the `Root\Microsoft\Windows\TaskScheduler` namespace with `RegisterByXml` method

2. **Command-line pattern matching** - Alert on Security 4688 process creation events where PowerShell command lines contain `Invoke-CimMethod`, `PS_ScheduledTask`, and `RegisterByXml` parameters together

3. **Task Scheduler operational log monitoring** - Monitor Task Scheduler EID 106 (task registered) events, particularly those registered by computer accounts or unexpected user contexts

4. **Registry-based task creation detection** - Alert on Sysmon EID 13 registry writes to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\` paths for new task registration

5. **Scheduled task file creation monitoring** - Monitor Sysmon EID 11 file creation events in `C:\Windows\System32\Tasks\` directory, especially by svchost.exe processes

6. **PowerShell execution policy bypass detection** - Correlate the `Set-ExecutionPolicy Bypass` commands (EID 4103) with subsequent task creation activities as an evasion indicator

7. **Privilege escalation context analysis** - Monitor Security 4703 token privilege adjustment events when PowerShell processes acquire scheduling-related privileges before task creation
