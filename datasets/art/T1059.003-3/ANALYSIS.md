# T1059.003-3: Windows Command Shell — Suspicious Execution via Windows Command Shell

## Technique Context

T1059.003 (Windows Command Shell) represents adversary use of cmd.exe to execute commands, scripts, or other executables. This technique is fundamental to Windows post-exploitation activities, as attackers frequently leverage cmd.exe for discovery, lateral movement, persistence, and data collection. The detection community focuses on suspicious command-line patterns, parent-child process relationships, obfuscation techniques, and execution from unusual locations or contexts. This particular test ("Suspicious Execution via Windows Command Shell") demonstrates obfuscated command execution using environment variable substring expansion (`%LOCALAPPDATA:~-3,1%md`) to dynamically construct the `cmd` command, a technique used to evade static detection rules.

## What This Dataset Contains

This dataset captures a PowerShell-initiated cmd.exe execution with command-line obfuscation. The core activity is visible in Security event 4688, showing PowerShell (PID 12168) spawning cmd.exe (PID 10144) with the obfuscated command line:

`"cmd.exe" /c %LOCALAPPDATA:~-3,1%md /c echo Hello, from CMD! > hello.txt & type hello.txt`

The obfuscation technique uses `%LOCALAPPDATA:~-3,1%` to extract the character "c" from the LOCALAPPDATA environment variable, constructing "cmd" dynamically. Sysmon event 1 confirms this with the matching process creation, tagged with `technique_id=T1059.003,technique_name=Windows Command Shell`.

The execution chain shows cmd.exe spawning a child cmd.exe process (PID 11772) with the deobfuscated command `cmd /c echo Hello, from CMD!`, demonstrating successful obfuscation bypass. File creation is captured in Sysmon event 11, showing the creation of `C:\Windows\Temp\hello.txt`. Process access events (Sysmon event 10) reveal PowerShell accessing both spawned processes with full access rights (0x1FFFFF), tagged as potential DLL injection activity.

## What This Dataset Does Not Contain

The dataset lacks network activity, registry modifications, or additional persistence mechanisms that might accompany real-world cmd.exe abuse. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass scriptblocks) rather than the actual PowerShell commands that initiated the cmd.exe execution. There are no Windows Defender blocks or alerts, indicating this obfuscation technique successfully evaded real-time protection. The technique operates entirely within expected system boundaries, using legitimate Windows utilities in their intended locations.

## Assessment

This dataset provides excellent telemetry for detecting obfuscated command-line execution. The Security 4688 events with full command-line logging capture the obfuscation pattern clearly, while Sysmon events 1 and 10 provide additional process relationship context and behavioral indicators. The combination of command-line obfuscation detection (Security logs) and process behavior analysis (Sysmon) creates multiple detection opportunities. The data quality is high for building detections around environment variable substring manipulation and suspicious parent-child process relationships involving cmd.exe.

## Detection Opportunities Present in This Data

1. **Environment Variable Substring Obfuscation** - Detect command lines containing environment variable substring syntax (`%VAR:~offset,length%`) in Security 4688 and Sysmon 1 events, particularly when combined with common Windows executables

2. **Suspicious PowerShell to CMD Process Chain** - Alert on PowerShell spawning cmd.exe with complex command-line arguments containing redirection operators and multiple commands chained with `&` or `&&`

3. **Dynamic Command Construction** - Identify patterns where environment variable manipulation results in executable names (cmd, powershell, etc.) being constructed dynamically

4. **File Creation from Command Shell** - Monitor Sysmon 11 events for cmd.exe creating files in temporary directories, especially when preceded by obfuscated command execution

5. **Process Access Patterns** - Detect PowerShell processes accessing newly spawned cmd.exe processes with full access rights (0x1FFFFF) as captured in Sysmon 10 events

6. **Command-Line Complexity Scoring** - Flag cmd.exe executions with high complexity scores based on special characters, environment variable usage, and command chaining

7. **Parent Process Context** - Alert on cmd.exe execution from PowerShell with obfuscated arguments, particularly when the parent PowerShell process lacks corresponding script block logging
