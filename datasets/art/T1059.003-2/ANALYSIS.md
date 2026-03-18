# T1059.003-2: Windows Command Shell — Writes text to a file and displays it.

## Technique Context

T1059.003 (Windows Command Shell) represents adversary execution of commands through the Windows Command Processor (cmd.exe). This technique is fundamental to Windows-based attacks, as cmd.exe provides direct access to the operating system command interface and is present on all Windows systems. Attackers commonly leverage cmd.exe for initial system reconnaissance, file operations, registry manipulation, and as a stepping stone to other malicious activities. The detection community focuses on monitoring cmd.exe execution patterns, particularly unusual command-line arguments, execution from unexpected parent processes, and commands that perform reconnaissance or file system manipulation. This technique often appears early in attack chains and can indicate both automated malware behavior and hands-on-keyboard adversary activity.

## What This Dataset Contains

This dataset captures a benign demonstration of T1059.003 where PowerShell spawns cmd.exe to write text to a file and display its contents. The Security event logs show the complete process lifecycle with Security EID 4688 capturing cmd.exe creation with the full command line: `"cmd.exe" /c echo "Hello from the Windows Command Prompt!" > "%TEMP%\test.bin" & type "%TEMP%\test.bin"`. The parent process is PowerShell (PID 9636) running as NT AUTHORITY\SYSTEM. Sysmon EID 1 provides complementary process creation telemetry with ProcessGuid {9dc7570a-57f9-69b4-302e-000000001000} and the same command line, correctly tagged with RuleName "technique_id=T1059.003,technique_name=Windows Command Shell". 

Sysmon EID 11 captures the file creation event showing cmd.exe writing to `C:\Windows\Temp\test.bin` with RuleName "technique_id=T1574.010,technique_name=Services File Permissions Weakness" (likely a false positive rule match). The dataset also includes Sysmon EID 10 process access events showing PowerShell accessing both the whoami.exe and cmd.exe processes with full access rights (0x1FFFFF), which represents normal parent process behavior for process creation and management.

## What This Dataset Does Not Contain

The dataset lacks network telemetry, as this particular cmd.exe execution performs only local file operations without network connectivity. Registry access events are not present, since the test doesn't involve registry modifications. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual PowerShell commands that launched cmd.exe. While Security 4688 events provide complete process creation coverage, some intermediate processes or child process spawns might not appear in Sysmon ProcessCreate events due to the include-mode filtering that only captures processes matching known-suspicious patterns. File access events beyond the creation operation (such as file reads via the `type` command) are not captured, as the sysmon-modular configuration doesn't monitor all file system operations.

## Assessment

This dataset provides excellent telemetry for detecting T1059.003 execution. The combination of Security 4688 events with full command-line logging and Sysmon ProcessCreate events offers comprehensive visibility into cmd.exe spawning patterns. The command line captured in both sources clearly shows the technique in action, including file redirection operators and command chaining with the `&` operator. The process tree relationship between PowerShell and cmd.exe is well-documented, enabling parent-child process analysis. The file creation events provide additional context about the technique's impact. The dataset would be strengthened by including more diverse cmd.exe execution patterns, commands with different privilege levels, and examples of cmd.exe being spawned by different parent processes beyond PowerShell.

## Detection Opportunities Present in This Data

1. **Cmd.exe Process Creation Monitoring** - Security EID 4688 and Sysmon EID 1 events detecting cmd.exe spawning with suspicious command-line patterns, particularly those involving file redirection (`>`), command chaining (`&`), or execution from unexpected parent processes.

2. **Command Line Analysis** - Pattern matching on the Process Command Line field to identify reconnaissance commands, file manipulation operations, or encoded/obfuscated command sequences within cmd.exe executions.

3. **Parent Process Relationships** - Correlating PowerShell to cmd.exe spawning patterns, which can indicate script-based execution or living-off-the-land techniques where legitimate tools spawn command shells.

4. **Temporary File Creation** - Sysmon EID 11 file creation events in temporary directories (`%TEMP%`) that correlate with cmd.exe execution, potentially indicating file staging or output redirection behaviors.

5. **Process Access Pattern Analysis** - Sysmon EID 10 events showing PowerShell accessing cmd.exe processes with full rights, which can help identify process injection attempts or abnormal parent-child process relationships.

6. **Command Execution Frequency** - Baseline analysis of normal cmd.exe execution patterns to identify anomalous spikes in command shell activity or execution during non-business hours.
