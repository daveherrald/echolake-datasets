# T1059-1: Command and Scripting Interpreter — AutoIt Script Execution

## Technique Context

T1059 Command and Scripting Interpreter encompasses adversaries' use of command-line interfaces and scripting languages for execution. AutoIt is a legitimate automation scripting language primarily used for Windows GUI automation and system administration. Attackers abuse AutoIt because compiled AutoIt scripts (.au3 files executed by AutoIt3.exe) can evade basic signature-based detection while providing full system access capabilities. The detection community focuses on monitoring AutoIt3.exe process creation, especially when executing scripts from unusual locations, and analyzing the parent-child process relationships that indicate script-based execution rather than legitimate automation tasks.

## What This Dataset Contains

This dataset captures a failed AutoIt script execution attempt. The Security channel shows the PowerShell command line attempting to execute AutoIt: `"powershell.exe" & {Start-Process -FilePath \"C:\Program Files (x86)\AutoIt3\AutoIt3.exe\" -ArgumentList \"C:\AtomicRedTeam\atomics\T1059\src\calc.au3\"}` (EID 4688). However, PowerShell EID 4100 shows the execution failed with "This command cannot be run due to the error: The system cannot find the file specified," indicating AutoIt3.exe is not installed at the expected path. The PowerShell script block logging captured the attempted Start-Process command with the AutoIt executable path and calc.au3 script argument. Sysmon captured extensive PowerShell process activity including .NET runtime loading, Windows Defender integration, and process access events, but no AutoIt3.exe process creation since the file doesn't exist on the system.

## What This Dataset Does Not Contain

The dataset lacks the actual AutoIt script execution because AutoIt3.exe is not installed on the test system. We don't see the target AutoIt3.exe process creation, the calc.au3 script loading, or any calculator application launching that would result from successful execution. There's no file system activity showing AutoIt script compilation or temporary file creation that typically accompanies AutoIt execution. The Sysmon ProcessCreate events don't include AutoIt3.exe because the sysmon-modular configuration's include-mode filtering wouldn't necessarily capture it, but more importantly because the process never started due to the missing executable.

## Assessment

This dataset has limited utility for AutoIt-specific detection engineering since the technique execution failed at the initial stage. However, it provides valuable telemetry for detecting attempted AutoIt abuse through PowerShell, which is a common attack vector. The Security channel's command-line logging and PowerShell script block logging both clearly show the intended AutoIt execution with suspicious script paths. The failure mode actually demonstrates how environmental prerequisites affect technique execution and provides insight into how attackers might probe for available scripting interpreters. Detection engineers can use this data to build rules that identify AutoIt execution attempts regardless of whether the execution succeeds.

## Detection Opportunities Present in This Data

1. **PowerShell AutoIt Execution Attempts** - Security EID 4688 and PowerShell EID 4104 showing Start-Process cmdlet with AutoIt3.exe file path and .au3 script arguments
2. **Suspicious Script Paths** - Command lines referencing AtomicRedTeam directory structure and calc.au3 script indicating test/attack tool usage
3. **PowerShell Start-Process for External Interpreters** - Script block logging showing Start-Process cmdlet targeting third-party scripting engines with file arguments
4. **Failed Execution Error Patterns** - PowerShell EID 4100 "system cannot find file" errors when attempting to launch uncommon executables like AutoIt3.exe
5. **PowerShell Execution Policy Bypass** - PowerShell EID 4103 showing Set-ExecutionPolicy bypass preceding script interpreter launch attempts
