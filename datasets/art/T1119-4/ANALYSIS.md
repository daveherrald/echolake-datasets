# T1119-4: Automated Collection — Recon information for export with Command Prompt

## Technique Context

T1119 Automated Collection involves adversaries using automated tools or techniques to gather system and network information without manual intervention. This technique is commonly employed during the collection phase of an attack, where attackers seek to systematically extract valuable information from compromised systems. The detection community focuses on identifying patterns of multiple system interrogation commands executed in sequence, unusual file creation patterns in temporary directories, and the use of native Windows utilities for bulk information gathering. This particular test simulates an attacker using Command Prompt to execute multiple reconnaissance commands and export their output to text files for later exfiltration.

## What This Dataset Contains

The dataset captures a comprehensive automated collection sequence executed through PowerShell spawning cmd.exe. The Security log shows the full process chain with command-line logging: PowerShell (PID 23540) spawns `cmd.exe /c sc query type=service > %TEMP%\T1119_1.txt & doskey /history > %TEMP%\T1119_2.txt & wmic process list > %TEMP%\T1119_3.txt & tree C:\AtomicRedTeam\atomics > %TEMP%\T1119_4.txt`. This cmd.exe process then spawns four child processes in sequence: sc.exe for service enumeration, doskey.exe for command history, wmic.exe for process listing, and tree.com for directory structure mapping.

Sysmon EID 1 events capture the process creations with detailed command lines, including `whoami.exe` execution and the main collection command. The dataset shows creation of four output files (T1119_1.txt through T1119_4.txt) in `C:\Windows\Temp\` via Sysmon EID 11 events. Sysmon EID 10 events document PowerShell accessing both whoami.exe and cmd.exe processes with full access rights (0x1FFFFF). The data includes privilege escalation events (Security EID 4703) showing token rights adjustment for both PowerShell and WMIC processes with extensive system privileges enabled.

## What This Dataset Does Not Contain

The dataset lacks the actual content of the collected files - we see their creation but not what reconnaissance data was captured. There are no network connections showing potential data exfiltration, and the dataset doesn't include registry access events that might accompany more comprehensive system enumeration. The PowerShell logs contain only test framework boilerplate (Set-ExecutionPolicy, Set-StrictMode) rather than the actual collection commands. Some expected process creations like doskey.exe appear in Security events but lack corresponding Sysmon EID 1 events due to the sysmon-modular include-mode filtering that only captures processes matching suspicious patterns.

## Assessment

This dataset provides excellent visibility into automated collection techniques through multiple complementary data sources. The Security logs with command-line auditing capture the complete attack chain, while Sysmon adds process relationship details, file creation timestamps, and privilege escalation context. The combination of process creation events, file creation events, and process access events creates a rich detection surface. The data quality is high for building detections around sequential system enumeration commands, bulk file creation in temporary directories, and the characteristic process trees associated with automated collection.

## Detection Opportunities Present in This Data

1. Sequential execution of multiple reconnaissance commands (sc query, wmic process list, tree, doskey) within a short timeframe from the same parent process
2. Bulk creation of numbered output files (T1119_*.txt) in temporary directories with systematic naming patterns
3. Command line patterns combining multiple system enumeration tools with output redirection using "&" command chaining
4. Process access events showing PowerShell obtaining full access rights to spawned system utilities during collection operations
5. Token privilege escalation events (EID 4703) showing extensive system privileges being enabled for WMIC and other collection tools
6. Parent-child process relationships between PowerShell and cmd.exe spawning multiple system discovery utilities in sequence
7. File creation events in %TEMP% directories with reconnaissance-related naming conventions and rapid sequential timestamps
8. WMIC process execution with associated DLL loads including Windows Defender integration and WMI utilities indicating system enumeration activity
