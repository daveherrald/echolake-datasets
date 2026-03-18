# T1106-1: Native API — Execution through API - CreateProcess

## Technique Context

T1106 Native API encompasses adversary usage of Windows native APIs to execute malicious code, access system resources, or perform other operations. This technique is fundamental to many attacks because native APIs provide direct access to core system functionality without relying on higher-level abstraction layers that might be monitored or restricted. The specific test case here focuses on CreateProcess API usage — one of the most critical Windows APIs for process creation that attackers frequently leverage for lateral movement, persistence, and execution.

Detection engineers focus heavily on this technique because native API calls often bypass application-level security controls and can be difficult to distinguish from legitimate system activity. The CreateProcess API specifically is monitored for unusual parent-child process relationships, execution of unsigned binaries, and processes launched from suspicious locations.

## What This Dataset Contains

This dataset captures a complete execution chain demonstrating programmatic process creation via the CreateProcess API. The attack begins with PowerShell (PID 40576) spawning a command shell with the full command line: `"cmd.exe" /c C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /out:"%tmp%\T1106.exe" /target:exe "C:\AtomicRedTeam\atomics\T1106\src\CreateProcess.cs" & %tmp%/T1106.exe`. 

Security Event ID 4688 captures the compilation process where csc.exe (PID 13340) compiles the C# source code `CreateProcess.cs` into an executable `T1106.exe` in the temp directory. Sysmon Event ID 1 provides additional process creation details with rule matches for "technique_id=T1127,technique_name=Trusted Developer Utilities Proxy Execution" for the compiler usage.

The compiled binary T1106.exe (PID 14372) then executes and demonstrates the core technique by calling CreateProcess to spawn `cmd.exe /c calc.exe`. Sysmon captures this with Event ID 1 tagged as "technique_id=T1036,technique_name=Masquerading" due to the unsigned executable. The process access events (Sysmon Event ID 10) show the CreateProcess API calls with full access rights (0x1FFFFF) and detailed call traces through ntdll.dll and kernel32.dll.

The dataset includes file creation events (Sysmon Event ID 11) showing the compilation artifacts and the final T1106.exe binary creation at `C:\Windows\Temp\T1106.exe`. Security events capture the complete process tree with command-line arguments preserved, showing the progression from compilation to execution to the final calc.exe payload.

## What This Dataset Does Not Contain

The dataset lacks the actual C# source code content that would show the specific CreateProcess API parameters and implementation details. While we see the compilation of `CreateProcess.cs`, the PowerShell events contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual test execution script.

Network-related telemetry is absent since this technique focuses on local process creation rather than network activity. Registry modifications aren't captured as this technique doesn't involve persistence mechanisms. The Sysmon configuration's include-mode filtering means some legitimate system processes in the execution chain may not appear in ProcessCreate events, though Security 4688 events provide full coverage.

Windows Defender is active but doesn't block this execution, likely because it's using legitimate system tools (csc.exe) and the technique itself doesn't trigger behavioral detection rules during this short execution window.

## Assessment

This dataset provides excellent telemetry for detecting Native API usage specifically around CreateProcess calls. The combination of Security 4688 events with command-line logging and Sysmon process access events (Event ID 10) creates multiple detection layers. The process access events are particularly valuable as they capture the API call traces and access rights, providing direct evidence of CreateProcess usage.

The compilation phase generates additional detection opportunities through the Trusted Developer Utilities Proxy Execution pattern, making this a multi-faceted attack scenario. The preservation of command-line arguments and parent-child process relationships enables robust process tree analysis.

The main limitation is the brief execution timeframe which may not capture longer-term behavioral patterns, but for demonstrating the core CreateProcess technique, the telemetry is comprehensive and actionable.

## Detection Opportunities Present in This Data

1. **Unsigned executable creation and immediate execution** - Monitor for compilation of C# code followed by execution of the resulting unsigned binary from temp directories (csc.exe → T1106.exe execution pattern)

2. **Process access with full rights to spawned processes** - Alert on Sysmon Event ID 10 with GrantedAccess 0x1FFFFF from user-created executables to system processes, especially with kernel32.dll in the call trace

3. **Command shell spawning from non-standard parents** - Detect cmd.exe processes with `/c` parameter spawned by executables from temp directories or unsigned binaries

4. **Trusted developer tool proxy execution** - Monitor csc.exe usage outside of development environments, especially when output targets temp directories or when invoked via command shell chains

5. **Suspicious parent-child process relationships** - Flag PowerShell spawning compilation commands that immediately execute the compiled output, indicating potential code execution techniques

6. **File creation in temp directories followed by process execution** - Correlate Sysmon Event ID 11 file creation events with subsequent Event ID 1 process creation from the same file path within short time windows

7. **API call trace analysis** - Examine process access events with call traces containing CreateProcess-related function sequences (kernel32.dll, kernelbase.dll) from non-system processes
