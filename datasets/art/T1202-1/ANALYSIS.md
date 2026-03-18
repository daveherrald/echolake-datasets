# T1202-1: Indirect Command Execution — Indirect Command Execution - pcalua.exe

## Technique Context

T1202 Indirect Command Execution is a defense evasion technique where adversaries execute malicious commands through legitimate Windows utilities that can proxy execution, bypassing application controls and potentially evading monitoring. The Program Compatibility Assistant (`pcalua.exe`) is a signed Microsoft utility originally designed to help run legacy applications with compatibility settings. However, it can be abused to execute arbitrary binaries using its `-a` parameter, making it a valuable "Living off the Land" binary (LOLBin).

Attackers leverage pcalua.exe because it's digitally signed, commonly present on Windows systems, and may not trigger the same security alerts as direct execution of suspicious binaries. The detection community focuses on monitoring command-line patterns involving pcalua.exe with the `-a` flag, unusual parent-child process relationships, and execution of suspicious payloads through this proxy mechanism. This technique is particularly effective for bypassing application whitelisting solutions that trust signed Microsoft binaries.

## What This Dataset Contains

This dataset captures a successful execution of the pcalua.exe indirect command execution technique with excellent visibility across multiple data sources. The execution chain begins with PowerShell (PID 26396) launching `cmd.exe` with the command line `"cmd.exe" /c pcalua.exe -a calc.exe & pcalua.exe -a C:\Windows\System32\calc.exe`, as captured in Security event 4688.

The dataset shows two distinct pcalua.exe executions. The first uses a relative path (`pcalua.exe -a calc.exe`) while the second uses a full path (`pcalua.exe -a C:\Windows\System32\calc.exe`). Both successfully spawn calc.exe processes, demonstrating the technique's flexibility in handling different path specifications.

Sysmon provides rich telemetry including Sysmon EID 1 process creation events showing the complete process tree: PowerShell → cmd.exe → pcalua.exe → calc.exe. Two calc.exe processes are created with PIDs 24840 and 23156, each with their respective pcalua.exe parents. The Sysmon events include full command lines, process GUIDs for correlation, file hashes, and integrity levels.

Process access events (Sysmon EID 10) show PowerShell accessing both the whoami.exe and cmd.exe processes with full access rights (0x1FFFFF), providing visibility into the execution context. Multiple image load events (Sysmon EID 7) capture DLL loading patterns for the involved processes.

## What This Dataset Does Not Contain

The dataset lacks Sysmon ProcessCreate events for the pcalua.exe processes themselves, which is expected behavior given that the sysmon-modular configuration uses include-mode filtering for EID 1. Since pcalua.exe isn't specifically included in the known-suspicious patterns, these process creations are only visible in Security 4688 events, not Sysmon.

Network-related telemetry is absent as this test only demonstrates local process execution. There are no registry modifications, file system artifacts beyond the PowerShell profile data, or persistence mechanisms captured, as this is a simple proof-of-concept execution rather than a full attack scenario.

The PowerShell channel contains only standard test framework boilerplate (Set-ExecutionPolicy Bypass and Set-StrictMode commands), with no evidence of the actual technique execution commands. This suggests the indirect command execution was triggered through a different mechanism than direct PowerShell script execution.

## Assessment

This dataset provides excellent coverage for detecting T1202 indirect command execution via pcalua.exe. The combination of Security 4688 events with full command-line logging and Sysmon telemetry offers multiple detection vectors. The Security events capture the complete process execution chain with command-line arguments that clearly show the pcalua.exe abuse pattern, while Sysmon provides additional context through process relationships, file hashes, and timing correlation.

The presence of both relative and absolute path variations in a single execution makes this dataset particularly valuable for testing detection logic robustness. The clean execution without errors or access denials means the telemetry represents successful technique implementation rather than blocked attempts.

However, the missing Sysmon EID 1 events for pcalua.exe processes highlights the importance of Security 4688 logging as a complementary data source, especially when Sysmon configurations use selective process creation logging.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection**: Monitor Security 4688 events for `pcalua.exe` execution with the `-a` parameter, especially when the target application is not a legitimate legacy program requiring compatibility assistance.

2. **Parent-child process relationship anomalies**: Alert on cmd.exe or PowerShell spawning pcalua.exe, particularly when pcalua.exe subsequently launches executables like calc.exe, powershell.exe, or other potentially suspicious binaries.

3. **Process execution chaining**: Correlate process GUIDs across Sysmon events to identify execution chains involving pcalua.exe as an intermediate proxy process between a command shell and the final payload.

4. **Unsigned or suspicious target detection**: Flag pcalua.exe executions where the target binary (specified with `-a`) has suspicious characteristics such as being unsigned, recently created, or located in unusual directories.

5. **Frequency-based detection**: Monitor for multiple rapid pcalua.exe executions from the same parent process, which may indicate automated abuse or batch execution of malicious commands.

6. **Process access pattern analysis**: Use Sysmon EID 10 events to identify when processes are accessing pcalua.exe or its child processes with unusual access rights, potentially indicating process injection or manipulation attempts.
