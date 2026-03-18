# T1127-2: Trusted Developer Utilities Proxy Execution — Lolbin Jsc.exe compile javascript to dll

## Technique Context

T1127 - Trusted Developer Utilities Proxy Execution represents adversary abuse of legitimate developer tools to execute malicious code while evading security controls. The jsc.exe utility is Microsoft's JScript .NET compiler that can compile JavaScript source code into .NET assemblies (DLLs or executables). Attackers leverage jsc.exe because it's a signed Microsoft binary that typically bypasses application whitelisting and may not be monitored as closely as other execution vectors.

This technique is particularly effective for defense evasion because jsc.exe allows attackers to compile and execute arbitrary code through a trusted development tool. The detection community focuses on monitoring for unusual jsc.exe executions, especially when compiling to libraries (/t:library flag), file creation patterns of compiled outputs, and process ancestry chains that indicate non-development usage.

## What This Dataset Contains

This dataset captures the complete execution chain of jsc.exe compiling a JavaScript file to a DLL. The Security channel shows the full process lineage with command-line arguments: PowerShell (PID 13708) spawns cmd.exe with the command `"cmd.exe" /c copy "C:\AtomicRedTeam\atomics\T1127\src\LibHello.js" %TEMP%\LibHello.js & C:\Windows\Microsoft.NET\Framework\v4.0.30319\jsc.exe /t:library %TEMP%\LibHello.js`, which then executes jsc.exe (PID 28752) with `C:\Windows\Microsoft.NET\Framework\v4.0.30319\jsc.exe /t:library C:\Windows\TEMP\LibHello.js`.

Sysmon provides rich telemetry showing the jsc.exe process creation (EID 1) correctly tagged with `technique_id=T1127`, file operations including the JavaScript source file copy to `C:\Windows\Temp\LibHello.js` and the resulting DLL compilation to `C:\Windows\Temp\LibHello.dll` (EID 11 events). The dataset also captures jsc.exe spawning cvtres.exe (the Microsoft Resource File To Object Converter) as part of the normal compilation process.

Process access events (EID 10) show PowerShell accessing both the whoami.exe and cmd.exe processes with full access rights (0x1FFFFF), indicating the test framework monitoring spawned processes.

## What This Dataset Does Not Contain

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no evidence of the actual technique execution commands. The dataset lacks any Windows Defender blocking activity—all processes execute successfully with exit code 0x0, indicating the technique completed without intervention.

Missing are network connections that might occur if the compiled DLL were loaded and executed, registry modifications that could indicate persistence mechanisms, and any subsequent execution of the compiled LibHello.dll itself. The Sysmon configuration's include-mode filtering for ProcessCreate events successfully captured the relevant LOLBin executions (jsc.exe, cmd.exe, cvtres.exe) but may have missed other ancillary processes.

## Assessment

This dataset provides excellent visibility into the T1127.2 technique execution. The combination of Security event 4688 process creation with full command-line logging and Sysmon's targeted process monitoring creates comprehensive coverage of the attack chain. The file creation events clearly show both the staging of malicious JavaScript code and the compilation output, while process ancestry tracking reveals the complete execution flow.

The telemetry quality is particularly strong for detection engineering because it captures the key indicators: jsc.exe execution with compilation flags, temporary file staging patterns, and the resulting DLL creation. The presence of both Security and Sysmon data provides redundancy and different analytical perspectives on the same technique.

## Detection Opportunities Present in This Data

1. **jsc.exe Process Execution with Library Compilation** - Monitor for jsc.exe execution with /t:library flag, especially when parent process is not a typical development environment (Visual Studio, MSBuild)

2. **Suspicious jsc.exe Process Ancestry** - Detect jsc.exe spawned by cmd.exe, PowerShell, or other script interpreters rather than development tools

3. **Temporary File Staging to System Directories** - Alert on JavaScript file creation in Windows temp directories followed by immediate compilation activities

4. **Rapid File Creation Sequence** - Monitor for JavaScript source file creation immediately followed by corresponding DLL compilation in the same directory

5. **Process Access Pattern** - Detect PowerShell or script processes accessing newly spawned jsc.exe processes with full access rights, indicating potential process monitoring or injection preparation

6. **cvtres.exe Spawned by jsc.exe** - Monitor for the cvtres.exe resource converter being spawned by jsc.exe as part of compilation, especially outside of development contexts

7. **DLL Creation in Temp Directories** - Alert on compiled .NET assembly creation in temporary directories, particularly when preceded by jsc.exe execution
