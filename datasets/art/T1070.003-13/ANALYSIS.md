# T1070.003-13: Clear Command History — Set Custom AddToHistoryHandler to Avoid History File Logging

## Technique Context

T1070.003 Clear Command History is a defense evasion technique where adversaries attempt to hide their activities by clearing or preventing the logging of command history. PowerShell maintains command history in several ways: in-memory session history, PSReadLine history files, and transcript logs. The PSReadLine module's `AddToHistoryHandler` parameter allows customization of what commands get added to the persistent history file, making it a powerful mechanism for preventing command logging.

Detection engineering typically focuses on monitoring PowerShell script block logging for history manipulation commands, process creation events showing suspicious PowerShell executions, and file system changes to history files. The technique is particularly concerning because it can be implemented programmatically within PowerShell scripts to prevent detection of subsequent malicious commands.

## What This Dataset Contains

This dataset captures the execution of a PowerShell command that sets a custom `AddToHistoryHandler` to prevent command history logging. The core technique is visible in multiple telemetry sources:

**PowerShell Script Block Logging (EID 4104):** The technique execution is clearly captured in script block `a2928238-bfe8-4b08-8ac4-3ca7dcaccf3c` with the content from the PowerShell profile: `C:\Windows\system32\config\systemprofile\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`. The actual technique command appears in script block `07b83ec6-2e1f-4a54-b97e-28513ad668ed`: `& {Set-PSReadLineOption -AddToHistoryHandler { return $false }}` and script block `4591babc-621e-4dde-ba30-6346a245af72`: `{Set-PSReadLineOption -AddToHistoryHandler { return $false }}`.

**PowerShell Module Logging (EID 4103):** Command invocation logging shows `Set-PSReadLineOption` being called with `AddToHistoryHandler` parameter set to `System.Func`2[System.String,System.Object]` in runspace `bbdc4145-9a13-4319-a254-eddbf854a89b`.

**Security Process Creation (EID 4688):** Shows PowerShell process creation with command line `"powershell.exe" & {Set-PSReadLineOption -AddToHistoryHandler { return $false }}` (Process ID 0x9798).

**Sysmon Process Creation (EID 1):** Captures the child PowerShell process (ProcessGuid `{9dc7570a-5ae4-69b4-9432-000000001000}`, PID 38808) with the suspicious command line, along with a `whoami.exe` execution (ProcessGuid `{9dc7570a-5ae4-69b4-9332-000000001000}`, PID 16940).

## What This Dataset Does Not Contain

The dataset lacks several elements that would strengthen detection coverage. There are no file system events showing the creation or modification of PowerShell history files (`ConsoleHost_history.txt` or similar), which would normally occur during regular PowerShell usage but are prevented by this technique. The dataset also doesn't include registry modifications that might accompany more sophisticated history manipulation techniques.

The PowerShell channel contains mostly test framework boilerplate script blocks with `Set-StrictMode -Version 1` patterns across multiple script block IDs, indicating significant filtering or cleanup of the telemetry. Additional context around the persistence of this configuration (such as profile modifications) beyond the single profile read event is not captured.

## Assessment

This dataset provides excellent visibility into the T1070.003 technique execution through multiple complementary data sources. The combination of PowerShell script block logging, module logging, and process creation events creates a robust detection foundation. The clear capture of the `Set-PSReadLineOption -AddToHistoryHandler` command with the `return $false` handler provides unambiguous evidence of history manipulation intent.

The telemetry quality is particularly strong for detecting this specific variant of command history clearing, though it would benefit from file system monitoring of history file locations to capture the absence of expected logging activity. The process creation events provide good context for behavioral analysis and parent-child process relationships.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Pattern Matching**: Monitor EID 4104 for script blocks containing `Set-PSReadLineOption` with `-AddToHistoryHandler` parameter, especially when the handler function returns `$false` or other values that would suppress history logging.

2. **PowerShell Module Command Monitoring**: Alert on EID 4103 CommandInvocation events for `Set-PSReadLineOption` cmdlet with `AddToHistoryHandler` parameter bindings, particularly when the parameter type indicates a custom function.

3. **Suspicious PowerShell Command Line Patterns**: Monitor process creation events (EID 4688/1) for PowerShell executions with command lines containing `AddToHistoryHandler` and `return $false` patterns.

4. **PowerShell Profile Modification Detection**: Track file creation/modification events for PowerShell profile paths (`Microsoft.PowerShell_profile.ps1`) combined with script block logging showing history manipulation commands.

5. **Process Tree Analysis**: Correlate parent PowerShell processes executing history manipulation commands with child processes that may contain the actual malicious activity (like the `whoami.exe` execution in this dataset).

6. **PowerShell Session Correlation**: Use PowerShell runspace IDs and process GUIDs to correlate history manipulation commands with subsequent PowerShell activity in the same session that should have been logged but wasn't.
