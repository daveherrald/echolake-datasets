# T1010-1: Application Window Discovery — List Process Main Windows - C# .NET

## Technique Context

T1010 Application Window Discovery involves adversaries enumerating visible windows and their associated processes to understand the current user environment. This technique helps attackers identify running applications, active sessions, and potential targets for further exploitation. The detection community focuses on monitoring for unusual window enumeration API calls (EnumWindows, GetWindowText), abnormal process inspection patterns, and .NET applications performing GUI reconnaissance. This specific test compiles and executes a C# program that uses Windows API functions to discover application windows, making it a representative example of how malware might perform desktop environment reconnaissance.

## What This Dataset Contains

This dataset captures a complete Application Window Discovery attack sequence using a compiled C# .NET application. The process chain shows PowerShell spawning cmd.exe with command `"cmd.exe" /c C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe -out:%TEMP%\T1010.exe "C:\AtomicRedTeam\atomics\T1010\src\T1010.cs" & %TEMP%\T1010.exe`, followed by csc.exe compilation and execution of T1010.exe. Security event 4688 captures the complete compilation process, including csc.exe with command line `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe -out:C:\Windows\TEMP\T1010.exe "C:\AtomicRedTeam\atomics\T1010\src\T1010.cs"` and the final execution of `C:\Windows\TEMP\T1010.exe`. Sysmon EID 1 events show the process creation chain with appropriate rule matches including technique_id=T1127 for csc.exe (Trusted Developer Utilities Proxy Execution) and technique_id=T1036 for T1010.exe (Masquerading). The dataset includes Sysmon EID 11 file creation events showing temporary files during compilation (`C:\Windows\Temp\CSC1030ED11E0D480D9F2B13295D1A8B4F.TMP`, `C:\Windows\SystemTemp\RES6752.tmp`) and the final executable creation (`C:\Windows\Temp\T1010.exe`). Sysmon EID 5 captures the process termination of T1010.exe, indicating successful execution and completion.

## What This Dataset Does Not Contain

The dataset lacks the actual window enumeration telemetry that would show the Application Window Discovery behavior in action. There are no API call traces showing EnumWindows, GetWindowText, or similar GUI reconnaissance functions that would indicate the T1010.exe process actively discovering application windows. Network connections, registry modifications, or file system access patterns that might reveal discovered window information are not present. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than technique-specific PowerShell activity. Windows Defender did not block this technique, as evidenced by successful compilation and execution with normal exit codes, so there's no EDR blocking telemetry to analyze.

## Assessment

This dataset provides excellent visibility into the delivery mechanism and compilation phase of the Application Window Discovery technique but lacks evidence of the actual discovery behavior. The Security 4688 events with full command-line logging and Sysmon ProcessCreate events offer strong detection opportunities for the compilation and execution phases. The file creation events during .NET compilation provide additional forensic context. However, for a complete T1010 detection strategy, this data would need supplementation with API monitoring or process behavior analysis that captures the actual window enumeration activities performed by the executed binary.

## Detection Opportunities Present in This Data

1. **C# Compiler Abuse Detection** - Monitor Security 4688 events for csc.exe execution with `-out:` parameters targeting temp directories, particularly when spawned from script interpreters

2. **Temporary Executable Creation** - Alert on Sysmon EID 11 file creation events where executables are created in `%TEMP%` or `C:\Windows\Temp\` directories by compilation processes

3. **Command Line Analysis for Compilation Chains** - Detect Security 4688 command lines containing both csc.exe compilation and immediate execution patterns using `&` operators

4. **Process Chain Analysis** - Monitor for PowerShell → cmd.exe → csc.exe → [unknown executable] process chains, especially when the final executable lacks code signing

5. **Sysmon Rule Correlation** - Leverage existing Sysmon rule matches for T1127 (Trusted Developer Utilities Proxy Execution) combined with T1036 (Masquerading) to identify suspicious compilation activities

6. **Unsigned Executable Execution** - Track Sysmon EID 1 events for unsigned executables (Signed: false) executing from temporary directories with minimal file metadata

7. **CVtres.exe Child Process Detection** - Monitor for cvtres.exe spawned by csc.exe as an indicator of active .NET compilation, particularly in non-development environments
