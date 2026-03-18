# T1070.003-11: Clear Command History — Prevent Powershell History Logging

## Technique Context

T1070.003 Clear Command History is a defense evasion technique where adversaries attempt to hide their tracks by clearing or disabling command history mechanisms. This particular test focuses on preventing PowerShell history logging by using the `Set-PSReadlineOption -HistorySaveStyle SaveNothing` command. PowerShell's PSReadLine module normally saves command history to files like `ConsoleHost_history.txt`, creating a forensic trail of attacker activities. By setting the history save style to "SaveNothing," attackers can prevent their subsequent PowerShell commands from being logged to disk, making incident response and threat hunting more difficult. This technique is commonly used by sophisticated adversaries who want to minimize their forensic footprint on compromised systems.

## What This Dataset Contains

This dataset captures a successful execution of the PowerShell history prevention technique. The key evidence appears in Security event 4688 showing the PowerShell process creation with command line `"powershell.exe" & {Set-PSReadlineOption -HistorySaveStyle SaveNothing}` (PID 37608). PowerShell event 4103 records the actual cmdlet invocation: `CommandInvocation(Set-PSReadLineOption): "Set-PSReadLineOption" ParameterBinding(Set-PSReadLineOption): name="HistorySaveStyle"; value="SaveNothing"`. Multiple PowerShell 4104 script block events capture the execution, including the key script block `{Set-PSReadlineOption -HistorySaveStyle SaveNothing}` with ID 3c581494-e196-46d2-acf0-448facb912df. Sysmon provides complementary process creation data with event 1 showing the PowerShell process launch. The dataset also contains evidence of a `whoami.exe` execution (PID 35952) likely used to verify the execution context before the history manipulation.

## What This Dataset Does Not Contain

The dataset doesn't contain evidence of the technique's effectiveness - specifically, we don't see the absence of subsequent command history that would normally be written to PSReadLine history files. There are no file system events showing the creation or modification of PowerShell history files, which would help demonstrate the technique's impact. The dataset also lacks any registry modifications that might be associated with PowerShell logging configuration changes. While we see the command execution, we don't have visibility into whether other PowerShell history mechanisms (like transcript logging) remain active or if only PSReadLine history is affected.

## Assessment

This dataset provides excellent telemetry for detecting the PowerShell history manipulation technique. The combination of Security 4688 command-line logging, PowerShell 4103 command invocation logs, and PowerShell 4104 script block logging creates multiple detection opportunities. The command-line arguments in Security events are particularly valuable as they clearly show the suspicious `Set-PSReadlineOption -HistorySaveStyle SaveNothing` parameter combination. The PowerShell operational logs provide the most detailed view of the technique execution, capturing both the cmdlet invocation and the script block content. Sysmon's process creation events add additional process genealogy context. This is a strong dataset for building robust detections against this evasion technique.

## Detection Opportunities Present in This Data

1. Monitor Security 4688 events for PowerShell processes with command lines containing `Set-PSReadlineOption` combined with `HistorySaveStyle` and `SaveNothing` parameters
2. Alert on PowerShell 4103 CommandInvocation events for `Set-PSReadLineOption` cmdlet with `HistorySaveStyle` parameter set to `SaveNothing`
3. Detect PowerShell 4104 script block events containing the string combination `Set-PSReadlineOption` and `SaveNothing`
4. Create process chain analysis rules for PowerShell spawning child PowerShell processes executing history manipulation commands
5. Monitor for PowerShell profile modifications that might make history prevention persistent (though not directly shown in this dataset)
6. Build behavioral analytics around PowerShell processes that execute `Set-PSReadlineOption` shortly after initial compromise indicators
7. Correlate history manipulation attempts with other suspicious PowerShell activities within the same session or timeframe
