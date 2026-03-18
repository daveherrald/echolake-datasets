# T1053.005-4: Scheduled Task — Powershell Cmdlet Scheduled Task

## Technique Context

T1053.005 - Scheduled Task is a persistence technique where adversaries create Windows scheduled tasks to execute malicious code at system startup, user logon, or other defined times. This technique is commonly used for maintaining persistence after initial access and can run with elevated privileges. Attackers often use PowerShell cmdlets like `New-ScheduledTaskAction`, `New-ScheduledTaskTrigger`, and `Register-ScheduledTask` for programmatic task creation, as these provide fine-grained control over task configuration while being less conspicuous than traditional `schtasks.exe` command-line usage. Detection engineers focus on monitoring PowerShell cmdlet execution, task registration events, registry modifications in the TaskCache, and file creation in the Tasks directory.

## What This Dataset Contains

This dataset captures a successful PowerShell-based scheduled task creation with comprehensive telemetry across multiple data sources:

**PowerShell Execution Chain**: Security 4688 shows the parent PowerShell process (PID 22952) spawning a child PowerShell process (PID 23424) with the full command line: `"powershell.exe" & {$Action = New-ScheduledTaskAction -Execute \"calc.exe\"; $Trigger = New-ScheduledTaskTrigger -AtLogon; $User = New-ScheduledTaskPrincipal -GroupId \"BUILTIN\Administrators\" -RunLevel Highest; ...}`

**PowerShell Cmdlet Telemetry**: PowerShell 4103 events capture invocation details for each ScheduledTask cmdlet:
- `New-ScheduledTaskAction` with Execute="calc.exe"
- `New-ScheduledTaskTrigger` with AtLogOn=True
- `New-ScheduledTaskPrincipal` with GroupId="BUILTIN\Administrators" and RunLevel="Highest"
- `Register-ScheduledTask` with TaskName="AtomicTask"

**Registry Modifications**: Sysmon 13 events show task registration in the TaskCache:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\AtomicTask\Id` = {9D3A146F-6034-45AD-98E8-F5D825333A04}
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\AtomicTask\Index` = 0x00000002

**File System Activity**: Sysmon 11 shows the task definition file created at `C:\Windows\System32\Tasks\AtomicTask` by svchost.exe (the Task Scheduler service).

**Task Scheduler Service Activity**: TaskScheduler 106 confirms successful task registration: "User 'ACME\ACME-WS02$' registered Task Scheduler task '\AtomicTask'".

**Library Loading**: Sysmon 7 captures taskschd.dll loading into WmiPrvSE.exe, indicating COM API usage for task operations.

## What This Dataset Does Not Contain

The dataset lacks several elements that would provide complete attack context:

**Execution Evidence**: No telemetry shows the scheduled task actually executing calc.exe, as this would require a logon trigger or manual execution after registration.

**Parent Process Context**: Missing the initial vector that launched the PowerShell test framework - the process chain stops at the test framework PowerShell.

**Cleanup Activities**: No events capture task deletion or modification after creation, which would be typical in a complete attack scenario.

**Network Activity**: No network connections from PowerShell processes, though this technique typically doesn't require network access.

**Advanced Persistence Indicators**: Missing evidence of more sophisticated techniques like task hijacking or modification of existing legitimate tasks.

## Assessment

This dataset provides excellent coverage for detecting PowerShell-based scheduled task creation. The combination of PowerShell command invocation logging (4103), process creation with full command lines (4688), registry modifications (Sysmon 13), file creation (Sysmon 11), and Task Scheduler service logs (106) creates multiple detection opportunities with minimal false positive risk. The task configuration requesting "Highest" run level and targeting the Administrators group represents a clear privilege escalation attempt. The telemetry quality is particularly strong because the technique completed successfully, generating the full attack chain rather than partial evidence from blocked attempts.

## Detection Opportunities Present in This Data

1. **PowerShell ScheduledTask Cmdlet Sequence**: Alert on PowerShell processes executing the sequence New-ScheduledTaskAction → New-ScheduledTaskTrigger → New-ScheduledTaskPrincipal → Register-ScheduledTask within a short timeframe, especially when creating tasks with elevated privileges.

2. **High-Privilege Task Registration**: Monitor TaskScheduler 106 events for task registration combined with PowerShell 4103 events showing RunLevel="Highest" or GroupId containing "Administrators" within the same process tree.

3. **Registry TaskCache Modifications**: Detect Sysmon 13 registry writes to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` from processes other than svchost.exe, indicating programmatic task manipulation.

4. **Suspicious Task File Creation**: Alert on Sysmon 11 file creation events in `C:\Windows\System32\Tasks\` with non-standard task names or created by PowerShell processes rather than the Task Scheduler service.

5. **Process Command Line Analysis**: Search Security 4688 events for PowerShell command lines containing "Register-ScheduledTask" combined with suspicious executables in the -Execute parameter (calc.exe, cmd.exe, powershell.exe, etc.).

6. **Cross-Channel Correlation**: Correlate PowerShell 4103 cmdlet invocations with TaskScheduler 106 registration events using process ID and timestamp proximity to identify programmatic task creation workflows.

7. **Privilege Escalation Context**: Monitor for scheduled tasks created with RunLevel "Highest" when the parent process is running under a lower privilege context, indicating potential privilege escalation attempts.
