# T1202-2: Indirect Command Execution — Indirect Command Execution - forfiles.exe

## Technique Context

T1202 (Indirect Command Execution) involves adversaries using utilities to proxy execution of malicious commands, bypassing security restrictions or evading detection. The `forfiles.exe` utility is a legitimate Windows tool designed to execute commands against files matching specific criteria, but attackers abuse its `/c` parameter to execute arbitrary commands. This technique is particularly valuable because forfiles.exe is a signed Microsoft binary that may be whitelisted in application control policies, and its legitimate purpose can mask malicious activity. The detection community focuses on unusual command-line patterns, unexpected parent-child process relationships, and forfiles executions that launch suspicious child processes rather than performing typical file operations.

## What This Dataset Contains

This dataset captures a successful forfiles.exe abuse execution with complete telemetry across multiple data sources. The attack chain begins with PowerShell (PID 29896) spawning `cmd.exe /c forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe` (Security EID 4688). The cmd.exe process (PID 26348) then launches `forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe` (Sysmon EID 1, PID 11044), which successfully executes calc.exe (PID 26996) as its child process. The complete process chain is: powershell.exe → cmd.exe → forfiles.exe → calc.exe, with all process creations captured in Security 4688 events with full command lines and Sysmon EID 1 events with process hashes and metadata. The dataset also contains PowerShell process access events (Sysmon EID 10) showing PowerShell accessing both whoami.exe and cmd.exe processes, likely for process management. File creation events show PowerShell startup profile data being written.

## What This Dataset Does Not Contain

The dataset lacks any defensive telemetry indicating Windows Defender blocked or flagged this activity, suggesting the technique executed without triggering real-time protection signatures. There are no network connections, registry modifications, or file system changes beyond the standard PowerShell profile data, indicating this was a simple proof-of-concept execution rather than a more complex attack. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without the actual malicious PowerShell commands that initiated the forfiles execution. No Application events or Windows Defender logs appear, suggesting minimal security product interaction.

## Assessment

This dataset provides excellent telemetry for detecting forfiles.exe abuse. The combination of Security 4688 process creation events with full command-line logging and Sysmon process creation events offers multiple detection vectors. The parent-child relationships are clearly documented, showing the suspicious use of forfiles to execute calc.exe rather than perform legitimate file operations. The technique successfully bypassed Windows Defender without generating any defensive alerts, making this valuable for understanding how such attacks can succeed in default Windows configurations. The process access events add additional context about PowerShell's interaction with spawned processes.

## Detection Opportunities Present in This Data

1. **Forfiles command execution abuse** - Security EID 4688 and Sysmon EID 1 showing forfiles.exe with `/c` parameter executing non-file-related commands like "calc.exe"

2. **Unusual forfiles parent process** - cmd.exe spawning forfiles.exe to execute applications rather than typical file management scenarios

3. **Forfiles child process anomalies** - calc.exe spawned as direct child of forfiles.exe, indicating command proxy execution rather than file operation

4. **PowerShell process chain leading to forfiles** - PowerShell → cmd.exe → forfiles.exe process lineage suggesting scripted abuse

5. **Forfiles command-line pattern** - Command line "forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe" showing file matching as pretext for command execution

6. **Process access from PowerShell to command execution chain** - Sysmon EID 10 showing PowerShell accessing cmd.exe process during forfiles execution sequence
