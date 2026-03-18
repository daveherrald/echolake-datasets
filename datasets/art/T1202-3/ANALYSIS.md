# T1202-3: Indirect Command Execution — Indirect Command Execution - conhost.exe

## Technique Context

T1202 Indirect Command Execution involves using legitimate system utilities to proxy execution of malicious code, helping attackers evade process-based detections that focus on common attack tools. The technique leverages trusted binaries to execute payloads indirectly, making the attack chain appear more legitimate. This specific test (T1202-3) demonstrates using conhost.exe to launch notepad.exe, showcasing how console host processes can be abused as execution proxies. Detection engineers typically focus on unusual parent-child relationships, command-line patterns where system utilities are used inappropriately, and process chains that deviate from normal system behavior.

## What This Dataset Contains

The dataset captures a clear indirect execution sequence through conhost.exe. Security event 4688 shows the key command execution: `"cmd.exe" /c conhost.exe "notepad.exe"` launched by PowerShell (PID 28688). The process chain flows from powershell.exe → cmd.exe → conhost.exe with the intention of launching notepad.exe. Sysmon captures two primary process creations: whoami.exe execution (EID 1, PID 30340) with command line `"C:\Windows\system32\whoami.exe"`, and the main technique execution through cmd.exe (EID 1, PID 44308) with the suspicious command line pattern. Process access events (EID 10) show PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF), indicating process injection activity. Multiple conhost.exe processes are referenced in Security 4689 exit events (PIDs 28924, 3452, 7036, 27708), showing the console host processes terminating after execution. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no technique-specific script blocks.

## What This Dataset Does Not Contain

Notably absent is any Sysmon ProcessCreate event for the actual conhost.exe execution that should have launched notepad.exe. This absence suggests either the sysmon-modular configuration filtered out conhost.exe as a non-suspicious process, or the execution failed/was blocked before the conhost.exe process could be created. There are no Sysmon events showing notepad.exe creation, indicating the indirect execution chain did not complete successfully. No file creation events suggest notepad.exe launching, no network connections, and no additional process access events targeting the intended notepad.exe process. The dataset also lacks any Windows Defender blocking events, despite real-time protection being active.

## Assessment

This dataset provides moderate value for detection engineering focused on indirect command execution patterns. The Security 4688 events capture the essential command-line evidence showing cmd.exe being used to launch conhost.exe with an argument, which is the core detection artifact for this technique. However, the dataset's utility is limited by the apparent execution failure — the technique appears to have been attempted but not completed successfully. The process access events from PowerShell provide additional context about the execution attempt, and the combination of Security and Sysmon events gives defenders multiple detection opportunities around the suspicious command pattern and parent-child relationships.

## Detection Opportunities Present in This Data

1. **Suspicious cmd.exe command line patterns** — Security 4688 showing `"cmd.exe" /c conhost.exe "notepad.exe"` which represents unusual use of conhost.exe with executable arguments

2. **Abnormal parent-child process relationships** — PowerShell spawning cmd.exe which attempts to spawn conhost.exe, deviating from typical console application launch patterns

3. **PowerShell process access to child processes** — Sysmon EID 10 events showing PowerShell accessing whoami.exe and cmd.exe with full permissions (0x1FFFFF), indicating potential process manipulation

4. **Conhost.exe process enumeration** — Multiple conhost.exe exit events in Security logs that can be correlated with the attempted execution timeline

5. **Command-line parameter analysis** — Detection of conhost.exe being invoked with executable file arguments rather than typical console hosting parameters
