# T1057-7: Process Discovery — Process Discovery (Process Discovery - Process Hacker) on Windows 11 Enterprise domain workstation

## Technique Context

T1057 Process Discovery is a fundamental reconnaissance technique where adversaries enumerate running processes to understand system activity, identify security tools, locate high-value targets, or find processes to inject into. Process Hacker is a popular open-source system information tool that provides detailed process information, making it attractive to both administrators and threat actors. Unlike built-in Windows utilities like tasklist or Get-Process, Process Hacker offers advanced capabilities including process memory inspection, handle enumeration, and detailed system resource monitoring. Detection engineers focus on monitoring for unusual process enumeration activity, especially when performed by non-administrative users or from suspicious parent processes, as excessive process discovery often precedes lateral movement or privilege escalation attempts.

## What This Dataset Contains

This dataset captures a failed attempt to launch Process Hacker via PowerShell. The key evidence shows:

**Process Creation Chain**: Security EID 4688 shows `powershell.exe` spawning a child PowerShell process with command line `"powershell.exe" & {Start-Process -FilePath \""$Env:ProgramFiles\Process Hacker 2\ProcessHacker.exe\""}`, followed by Sysmon EID 1 capturing the same process creation with full command-line arguments.

**PowerShell Script Block Evidence**: EID 4104 captures the actual technique execution: `& {Start-Process -FilePath "$Env:ProgramFiles\Process Hacker 2\ProcessHacker.exe"}` and `{Start-Process -FilePath "$Env:ProgramFiles\Process Hacker 2\ProcessHacker.exe"}`.

**Failure Telemetry**: PowerShell EID 4100 shows the error: `"This command cannot be run due to the error: The system cannot find the file specified"` and EID 4103 shows the Start-Process cmdlet invocation with `ParameterBinding(Start-Process): name="FilePath"; value="C:\Program Files\Process Hacker 2\ProcessHacker.exe"` followed by the terminating error.

**Process Access Attempts**: Sysmon EID 10 shows PowerShell accessing both `whoami.exe` (PID 12928) and another PowerShell process (PID 12048) with full access rights (0x1FFFFF), indicating the PowerShell execution context attempting process operations.

**Ancillary Process Discovery**: The test also executed `whoami.exe` as captured in Sysmon EID 1 and Security EID 4688, which represents basic system owner discovery as part of the reconnaissance activity.

## What This Dataset Does Not Contain

This dataset lacks the actual Process Hacker execution telemetry because the binary was not installed on the test system. Consequently, there are no events showing successful process enumeration activities such as:
- Process Hacker's own process creation and initialization
- Network connections to gather system information
- File system access to process executable paths
- Registry queries for process-related information
- Memory access patterns typical of advanced process inspection tools

The PowerShell channel contains primarily test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than detailed script execution logs of the actual technique implementation.

## Assessment

This dataset provides excellent visibility into failed tool deployment attempts but limited insight into successful T1057 Process Discovery techniques. The combination of Security 4688 process creation events, Sysmon process creation (EID 1), PowerShell script block logging (EID 4104), and error handling (EID 4100/4103) creates a comprehensive picture of the attack attempt. However, for detection engineering purposes focused on actual process discovery behavior, this dataset is more valuable for detecting preparation phases and failed execution attempts than successful reconnaissance activities. The process access events (Sysmon EID 10) provide some insight into PowerShell's process inspection capabilities, but don't represent the comprehensive process enumeration that Process Hacker would perform if successfully executed.

## Detection Opportunities Present in This Data

1. **PowerShell Start-Process with Security Tool Paths** - Monitor EID 4104 for Start-Process cmdlet usage targeting known security/administrative tools in Program Files directories, especially Process Hacker, Process Monitor, or similar utilities.

2. **Failed Process Execution with Security Tool Names** - Correlate PowerShell EID 4100 error messages containing "cannot find the file specified" with command lines referencing process inspection tools.

3. **Process Access from PowerShell Context** - Monitor Sysmon EID 10 for PowerShell processes accessing other processes with full rights (0x1FFFFF), particularly when combined with Start-Process cmdlet usage.

4. **Command Line Patterns for Process Discovery Tools** - Alert on Security EID 4688 command lines containing references to `ProcessHacker.exe`, `procexp.exe`, or other advanced process monitoring tools, especially with embedded quotes and environment variable expansion.

5. **PowerShell Module Invocation Sequences** - Monitor EID 4103 for Start-Process cmdlet invocations with FilePath parameters pointing to security tools, particularly when followed by terminating errors.

6. **Cross-Process PowerShell Execution Chain** - Detect PowerShell parent-child relationships where the child process attempts to launch external process discovery tools, indicating potential tool deployment attempts.
