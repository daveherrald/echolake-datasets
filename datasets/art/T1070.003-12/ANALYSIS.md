# T1070.003-12: Clear Command History — Clear Powershell History by Deleting History File

## Technique Context

T1070.003 Clear Command History is a defense evasion technique where adversaries attempt to clear or disable command history logging mechanisms to hide their activities. This specific test focuses on PowerShell history clearing by deleting the PSReadLine history file, which is commonly targeted because PowerShell command history can reveal sensitive information about adversary operations, including credentials, reconnaissance commands, and lateral movement activities.

The detection community focuses heavily on this technique because command history clearing is a strong indicator of adversary presence and intent to evade detection. Key detection opportunities include monitoring for PowerShell commands that interact with PSReadLine history files, file deletion events targeting history files, and process creation patterns involving history clearing cmdlets.

## What This Dataset Contains

This dataset captures a successful execution of PowerShell history clearing through file deletion. The core technique evidence appears in the PowerShell events, specifically EID 4103 and 4104:

- **PowerShell Script Block (EID 4104)**: `& {Remove-Item (Get-PSReadlineOption).HistorySavePath}` - the actual command used to clear history
- **Command Invocation (EID 4103)**: Shows `Get-PSReadLineOption` being called to retrieve the history file path: `"C:\Windows\system32\config\systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"`
- **Command Invocation (EID 4103)**: Shows `Remove-Item` attempting to delete the history file, with a `NonTerminatingError` indicating the file didn't exist: `"Cannot find path 'C:\Windows\system32\config\systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' because it does not exist."`

The Security channel (EID 4688) captures process creation showing the PowerShell command line: `"powershell.exe" & {Remove-Item (Get-PSReadlineOption).HistorySavePath}`.

Sysmon events provide additional process context:
- **Process Create (EID 1)**: PowerShell process with the full command line showing the history deletion attempt
- **Process Access (EID 10)**: PowerShell accessing child processes during execution
- **Image Load (EID 7)**: PowerShell loading .NET assemblies and Windows Defender components

## What This Dataset Does Not Contain

The dataset shows an unsuccessful history clearing attempt - the PSReadLine history file didn't exist at the time of execution, so no actual file deletion occurred. This means there are no:

- File deletion events (no Sysmon EID 23 for file deletion)
- Registry modifications related to PSReadLine configuration
- Evidence of successful history clearing (the error message indicates the file wasn't found)

The technique executed but had no impact because there was no existing history file to delete. This is common in automated test environments where PowerShell hasn't been used interactively to generate command history.

## Assessment

This dataset provides moderate utility for detection engineering focused on intent-based detection rather than impact-based detection. The PowerShell script block logging captures the exact technique being attempted, making it valuable for behavioral detection. The Security 4688 events with command-line logging provide complementary coverage for environments without PowerShell script block logging enabled.

However, the lack of actual file deletion limits its utility for testing detections that rely on file system events. The dataset would be stronger if it included scenarios where the history file exists and is successfully deleted, providing both attempt and success telemetry.

The combination of PowerShell detailed logging and Security process auditing provides solid coverage for detecting this technique regardless of success.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Analysis** - Monitor EID 4104 for script blocks containing `Remove-Item` combined with `Get-PSReadlineOption` or direct references to PSReadLine history paths

2. **PowerShell Command Invocation Monitoring** - Alert on EID 4103 CommandInvocation events for `Get-PSReadLineOption` followed by `Remove-Item` cmdlets in sequence

3. **Process Command Line Detection** - Monitor Security EID 4688 for PowerShell processes with command lines containing history clearing patterns like `Remove-Item (Get-PSReadlineOption).HistorySavePath`

4. **PSReadLine History File Path Targeting** - Watch for PowerShell operations targeting the standard PSReadLine history file paths (`ConsoleHost_history.txt` in `PSReadLine` directories)

5. **Defense Evasion Command Pattern** - Look for PowerShell script blocks or command lines that combine history enumeration and deletion operations in single commands or script blocks

6. **Nested PowerShell Process Creation** - Monitor for PowerShell spawning additional PowerShell processes with suspicious command lines containing history clearing operations
