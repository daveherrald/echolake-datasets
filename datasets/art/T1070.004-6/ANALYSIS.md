# T1070.004-6: File Deletion — Delete a single file - Windows PowerShell

## Technique Context

T1070.004 File Deletion is a defense evasion technique where adversaries delete files and directories to remove evidence of their presence or hinder forensic analysis. Within the broader T1070 Indicator Removal category, file deletion is one of the most common anti-forensics techniques used by attackers to cover their tracks. This specific test demonstrates using PowerShell's `Remove-Item` cmdlet to delete a single file, which is a common method for both legitimate system administration and malicious cleanup activities.

The detection community focuses on monitoring file deletion patterns, especially when targeting sensitive locations, system files, or security tools. However, distinguishing between legitimate administrative actions and malicious cleanup requires contextual analysis of the deletion activity, timing, and surrounding process behavior.

## What This Dataset Contains

This dataset captures a PowerShell-based file deletion attempt that ultimately fails because the target file doesn't exist. The core activity is visible in Security event 4688 showing the PowerShell process creation with command line `"powershell.exe" & {Remove-Item -path $env:TEMP\deleteme_T1551.004}`. 

The PowerShell operational logs contain the actual cmdlet execution in event 4103: `CommandInvocation(Remove-Item): "Remove-Item" ParameterBinding(Remove-Item): name="Path"; value="C:\Windows\TEMP\deleteme_T1551.004"` along with a `NonTerminatingError` indicating "Cannot find path 'C:\Windows\TEMP\deleteme_T1551.004' because it does not exist."

PowerShell script block logging (event 4104) captures the command structure: `& {Remove-Item -path $env:TEMP\deleteme_T1551.004}` and `{Remove-Item -path $env:TEMP\deleteme_T1551.004}`. Sysmon provides comprehensive process telemetry including process creation (event 1) for both the parent PowerShell process and the spawned child PowerShell process executing the deletion command, along with extensive image loading events (event 7) showing .NET framework and Windows Defender integration.

## What This Dataset Does Not Contain

This dataset lacks actual file deletion evidence because the target file `deleteme_T1551.004` doesn't exist in the system's TEMP directory. There are no Sysmon file deletion events (event 23) or successful file access patterns that would indicate actual file removal. The test appears to have a setup issue where the target file wasn't created before the deletion attempt.

Additionally, there are no filesystem audit events that would typically accompany successful file deletions when object access auditing is enabled. The absence of successful deletion telemetry limits this dataset's utility for understanding what successful file deletion looks like in the logs, though it does demonstrate how failed deletion attempts are captured.

## Assessment

This dataset provides moderate value for detection engineering, primarily demonstrating failed file deletion attempts rather than successful ones. The PowerShell operational logs are the strongest data source here, clearly showing the `Remove-Item` cmdlet invocation and the resulting error. Security event logs provide good process-level context with command-line visibility.

The dataset would be significantly stronger if it contained a successful deletion scenario, as most real-world detections need to identify when files are actually removed rather than just attempted. However, it does illustrate how PowerShell-based deletion attempts are logged across multiple data sources, which is valuable for understanding the telemetry landscape.

## Detection Opportunities Present in This Data

1. **PowerShell Remove-Item cmdlet usage** - Monitor PowerShell operational logs (event 4103) for `CommandInvocation(Remove-Item)` events, especially when targeting temporary directories or system locations.

2. **PowerShell script block analysis** - Alert on PowerShell script blocks (event 4104) containing `Remove-Item` cmdlet patterns, particularly when combined with environment variable expansion like `$env:TEMP`.

3. **Command-line based file deletion** - Monitor Security event 4688 process creation logs for PowerShell executions with command lines containing `Remove-Item` parameters.

4. **Process genealogy for cleanup activities** - Track parent-child relationships between PowerShell processes to identify potential multi-stage cleanup operations.

5. **Failed deletion attempts** - Monitor PowerShell error patterns in operational logs for failed file deletion attempts, which may indicate incomplete cleanup efforts or attempts to delete protected files.

6. **PowerShell execution policy bypasses** - Correlate `Set-ExecutionPolicy Bypass` events (visible in the logs) with subsequent file deletion cmdlets as potential indicators of scripted cleanup activities.
