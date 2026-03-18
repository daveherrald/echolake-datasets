# T1218.011-7: Rundll32 — Rundll32 setupapi.dll Execution

## Technique Context

T1218.011 focuses on the abuse of rundll32.exe, a legitimate Windows utility that loads and runs 32-bit DLLs. Attackers frequently leverage rundll32.exe for defense evasion because it's a trusted, signed Microsoft binary that can execute arbitrary code through DLL exports while potentially evading application whitelisting and behavioral detection. This specific test demonstrates using rundll32.exe with setupapi.dll's InstallHinfSection export to process a malicious INF file, a technique that can be used to execute commands, install software, or modify system configurations through Windows' setup infrastructure.

The detection community focuses on monitoring rundll32.exe command lines for suspicious DLL/export combinations, unusual parent processes, and INF file processing activities. SetupAPI-based techniques are particularly interesting because they can perform privileged operations and are less commonly monitored than other rundll32.exe abuse patterns.

## What This Dataset Contains

This dataset captures a successful rundll32.exe execution using setupapi.dll's InstallHinfSection function. The core technique evidence appears in Security event 4688 showing the rundll32.exe process creation: `rundll32.exe  setupapi.dll,InstallHinfSection DefaultInstall 128 "C:\AtomicRedTeam\atomics\T1218.011\src\T1218.011_DefaultInstall.inf"`.

The execution chain is clearly visible:
- PowerShell (PID 36328) spawns cmd.exe with the full rundll32 command
- cmd.exe (PID 35380) executes rundll32.exe with the setupapi.dll parameters  
- rundll32.exe (PID 26140) processes the INF file successfully (exit status 0x0)

Sysmon ProcessCreate events capture the same execution chain with rule matches for T1059.003 (Windows Command Shell), T1218.011 (rundll32.exe), and T1033 (System Owner/User Discovery). The dataset also includes ProcessAccess events (EID 10) showing PowerShell accessing both the spawned whoami.exe and cmd.exe processes.

The PowerShell channel contains typical Atomic Red Team test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no technique-specific PowerShell commands logged.

## What This Dataset Does Not Contain

This dataset lacks several types of telemetry that would provide deeper insight into the INF file processing:

- The actual INF file content referenced in the command line (`T1218.011_DefaultInstall.inf`) is not captured through file access or content monitoring
- SetupAPI-specific Windows events that might log INF installation activities are not present in the collected channels
- Any registry modifications, file installations, or system changes that may have been performed by the INF processing are not visible
- Network connections or other post-execution behaviors that might result from successful INF execution

The sysmon-modular configuration's include-mode filtering means we only see processes matching known-suspicious patterns, so any additional child processes spawned by rundll32.exe that don't match the detection rules would be missing from Sysmon EID 1 events.

## Assessment

This dataset provides strong evidence for detecting T1218.011 rundll32.exe abuse, particularly the setupapi.dll InstallHinfSection variant. The Security 4688 events with command-line logging capture the complete attack technique with sufficient detail for high-confidence detection. The process relationship data clearly shows the execution chain and parent-child relationships.

The main limitation is the lack of visibility into what the INF file actually accomplished—we can see that rundll32.exe was invoked to process an INF file, but not what system changes resulted. This limits the dataset's utility for understanding the full impact or developing detections for the consequences of INF processing rather than just the initial execution.

For detection engineering focused on the rundll32.exe execution vector itself, this dataset is excellent. For understanding INF-based persistence, privilege escalation, or system modification techniques, additional telemetry sources would strengthen the analysis.

## Detection Opportunities Present in This Data

1. **Rundll32.exe with setupapi.dll command-line detection** - Alert on rundll32.exe processes with "setupapi.dll,InstallHinfSection" in the command line, particularly with external INF file paths
2. **Rundll32.exe parent process anomalies** - Detect rundll32.exe spawned by cmd.exe or PowerShell, especially in automation contexts
3. **INF file processing from non-standard locations** - Monitor for INF files being processed from user-writable directories or temporary paths
4. **Process chain analysis** - Correlate PowerShell → cmd.exe → rundll32.exe execution chains as potential scripted attacks
5. **SetupAPI INF installation monitoring** - Baseline normal InstallHinfSection usage and alert on deviations in file paths, timing, or context
6. **Cross-reference with file creation events** - Look for rundll32.exe setupapi execution coinciding with suspicious file creation or registry modification patterns
