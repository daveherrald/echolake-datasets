# T1124-5: System Time Discovery — System Time with Windows time Command

## Technique Context

T1124 System Time Discovery is a fundamental reconnaissance technique where adversaries gather temporal information about compromised systems. Attackers use this technique to understand system timezone settings, coordinate multi-stage attacks across time zones, schedule persistence mechanisms, evade time-based security controls, and correlate activities with legitimate business hours. The technique is particularly common in initial discovery phases and persistence establishment.

The detection community focuses on monitoring command-line invocations of time-related utilities (`time`, `w32tm`, PowerShell time cmdlets), unusual process chains involving time discovery tools, and behavioral patterns where time discovery precedes other suspicious activities. This technique often appears in automated reconnaissance scripts and is frequently combined with other system discovery techniques.

## What This Dataset Contains

This dataset captures a straightforward execution of the Windows `time` command through PowerShell. The primary evidence appears in:

**Process Creation Events:** Security 4688 shows PowerShell (PID 32080) spawning `"cmd.exe" /c time` with exit status 0x1, indicating the command completed but potentially with an error (likely due to the interactive nature of the time command expecting user input).

**Sysmon ProcessCreate:** EID 1 captures the cmd.exe creation with command line `"cmd.exe" /c time`, providing the same process chain: `powershell.exe` → `cmd.exe /c time`.

**Process Access Events:** Sysmon EID 10 shows PowerShell accessing both whoami.exe (PID 1284) and cmd.exe (PID 41756) with full access rights (0x1FFFFF), indicating normal parent process monitoring behavior.

**Supporting Process Activity:** The dataset also captures a `whoami.exe` execution (likely part of the test framework setup), along with extensive PowerShell module loading and Windows Defender DLL injections.

## What This Dataset Does Not Contain

The dataset lacks the actual output of the time command, as Windows event logs don't capture stdout/stderr content. The cmd.exe process exits with status 0x1, suggesting it may have encountered an interactive prompt that couldn't be satisfied in the automated execution context. 

No Sysmon ProcessCreate events exist for the parent PowerShell process due to the include-mode filtering in sysmon-modular config, which only captures processes matching known-suspicious patterns. The PowerShell events (4103/4104) contain only test framework boilerplate (Set-ExecutionPolicy, Set-StrictMode) rather than the actual time discovery commands.

Registry access events, file system changes related to timezone data, or network connections are absent, indicating this was a simple local time query without additional persistence or exfiltration activities.

## Assessment

This dataset provides solid telemetry for detecting this specific variant of T1124. The combination of Security 4688 command-line logging and Sysmon ProcessCreate events delivers comprehensive coverage of the process execution chain. The command line `"cmd.exe" /c time` is highly specific and creates a clear detection signature.

However, the dataset would be stronger with successful command execution (exit code 0) and potentially multiple time discovery methods (PowerShell Get-Date, w32tm, direct registry queries). The current execution's error status (0x1) demonstrates how automated testing environments can produce different telemetry than manual execution.

## Detection Opportunities Present in This Data

1. **Command Line Pattern Detection** - Monitor Security 4688 or Sysmon EID 1 for command lines containing `cmd.exe /c time`, `time.exe`, or PowerShell time-related cmdlets

2. **Process Chain Analysis** - Detect PowerShell spawning cmd.exe specifically for time commands, which may indicate scripted reconnaissance

3. **Execution Context Anomalies** - Alert on time discovery commands executed from unexpected parent processes or in unusual directory contexts

4. **Behavioral Clustering** - Correlate time discovery with other system discovery techniques (whoami, systeminfo) within short time windows

5. **Exit Code Monitoring** - Track failed time command executions (exit code 0x1) which may indicate automated tools struggling with interactive prompts

6. **Parent Process Validation** - Flag time discovery commands launched from suspicious parent processes or those lacking expected business justification
