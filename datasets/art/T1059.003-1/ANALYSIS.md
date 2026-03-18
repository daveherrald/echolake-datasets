# T1059.003-1: Windows Command Shell — Create and Execute Batch Script

## Technique Context

T1059.003 (Windows Command Shell) represents one of the most fundamental execution techniques on Windows systems. Attackers use cmd.exe and batch scripts for initial access, persistence, privilege escalation, defense evasion, and lateral movement. The technique is prevalent because it requires no additional tools, leverages built-in Windows functionality, and can execute complex multi-stage attacks through batch scripting. Detection engineers focus on monitoring cmd.exe process creation, command-line arguments, parent-child relationships, and file operations related to batch script creation and execution. This technique often serves as a stepping stone to more sophisticated attack chains.

## What This Dataset Contains

This dataset captures a failed attempt to execute a batch script through PowerShell's Start-Process cmdlet. The core telemetry shows:

**PowerShell Command Execution**: Security EID 4688 shows PowerShell process creation with command line `"powershell.exe" & {Start-Process \""C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1059.003_script.bat\""}`. 

**PowerShell Script Block Logging**: EID 4104 captures the actual script execution attempt: `& {Start-Process "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1059.003_script.bat"}` and the Start-Process cmdlet invocation.

**Execution Failure**: PowerShell EID 4100 shows the technique failed with "Error Message = This command cannot be run due to the error: The system cannot find the file specified." The batch file `T1059.003_script.bat` doesn't exist at the expected path.

**Process Telemetry**: Sysmon EID 1 captures PowerShell process creation (PID 9584) with the full Start-Process command line. Multiple PowerShell processes are created during the test execution sequence.

**Ancillary Activity**: Sysmon EID 1 shows `whoami.exe` execution (likely part of the test framework), and extensive .NET/PowerShell DLL loading events (EID 7) as PowerShell initializes.

## What This Dataset Does Not Contain

**No Batch Script Creation**: There's no evidence of the target batch file being created or written to disk - the file simply doesn't exist.

**No cmd.exe Execution**: Since the batch file doesn't exist, cmd.exe is never spawned to execute it. This is the core T1059.003 behavior that should have been captured.

**No Batch Script Content**: We don't see what the batch script was supposed to contain or execute.

**Limited Process Chain**: The sysmon-modular config's include-mode filtering means we may be missing intermediate process creations that don't match suspicious patterns.

**No File System Monitoring**: Sysmon file creation events (EID 11) only show PowerShell profile data, not the expected batch file operations.

## Assessment

This dataset provides limited value for T1059.003 detection engineering because the core technique execution failed. However, it offers useful telemetry for detecting *attempted* batch script execution through PowerShell. The PowerShell command-line arguments, script block logging, and error messages provide clear indicators of malicious intent even when execution fails. The dataset is more valuable for PowerShell-based execution detection (T1059.001) than pure batch script execution. For robust T1059.003 detection development, you'd need a dataset where the batch file actually exists and executes successfully, generating cmd.exe processes and associated command-line telemetry.

## Detection Opportunities Present in This Data

1. **PowerShell Start-Process with Batch File Extensions**: Monitor EID 4688 command lines containing `Start-Process` with `.bat`, `.cmd`, or `.exe` extensions, especially from non-standard paths.

2. **PowerShell Script Block Batch Execution**: Alert on EID 4104 script blocks containing `Start-Process` combined with batch file extensions or command shell indicators.

3. **PowerShell Error Messages for Missing Malware**: Monitor EID 4100 for "system cannot find the file specified" errors when PowerShell attempts to execute files from suspicious paths like `\atomics\` or `\ExternalPayloads\`.

4. **Nested PowerShell Process Creation**: Flag EID 1 events where powershell.exe spawns additional powershell.exe processes with execution-related command lines.

5. **Execution Policy Bypass Attempts**: Correlate EID 4103 `Set-ExecutionPolicy Bypass` events with subsequent process execution attempts to identify script execution preparation.

6. **PowerShell Process Access Patterns**: Monitor EID 10 process access events where PowerShell processes access newly created processes with high privileges (0x1FFFFF), indicating potential process injection or monitoring.
