# T1027.004-1: Compile After Delivery — Compile After Delivery using csc.exe

## Technique Context

T1027.004 (Compile After Delivery) is a defense evasion technique where attackers deliver source code to target systems and compile it locally, rather than delivering pre-compiled executables. This approach helps evade signature-based detection and static analysis tools that rely on known executable hashes. The C# compiler (csc.exe) is particularly attractive to attackers because it's present on most Windows systems with .NET Framework and produces native Windows executables from source code.

The detection community focuses on monitoring compiler executions, especially when they occur in unusual contexts (spawned by scripts, writing to temporary directories, or compiling suspicious code). Key indicators include csc.exe process creation with suspicious command lines, file creation events for compiled outputs, and the compilation of code in non-development contexts.

## What This Dataset Contains

This dataset captures a successful T1027.004 execution with excellent telemetry coverage across all phases:

**Process Chain (Security 4688 events):**
- PowerShell spawns cmd.exe with command line: `"cmd.exe" /c C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\Windows\Temp\T1027.004.exe "C:\AtomicRedTeam\atomics\T1027.004\src\calc.cs"`
- cmd.exe spawns csc.exe with command line: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\Windows\Temp\T1027.004.exe "C:\AtomicRedTeam\atomics\T1027.004\src\calc.cs"`
- csc.exe spawns cvtres.exe (resource compiler) with command line: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 "/OUT:C:\Windows\SystemTemp\RESCB81.tmp"`

**Sysmon ProcessCreate Events (EID 1):**
- Sysmon captures whoami.exe, cmd.exe, and csc.exe process creation with detailed hashes and integrity levels
- csc.exe creation tagged with RuleName `technique_id=T1127,technique_name=Trusted Developer Utilities Proxy Execution`
- cmd.exe tagged with `technique_id=T1059.003,technique_name=Windows Command Shell`

**File Creation Events (Sysmon EID 11):**
- Temporary compilation files: `C:\Windows\Temp\CSCCA2781566D1C4A139EB146A9C98CAA0.TMP` and `C:\Windows\SystemTemp\RESCB81.tmp`
- Final compiled executable: `C:\Windows\Temp\T1027.004.exe`

**Process Access Events (Sysmon EID 10):**
- PowerShell accessing both whoami.exe and cmd.exe processes with GrantedAccess 0x1FFFFF

## What This Dataset Does Not Contain

The dataset lacks several elements that would provide additional detection opportunities:

- **No execution of the compiled binary** — the test compiles T1027.004.exe but doesn't execute it, so we miss post-compilation behavior
- **No network activity** — this is a local compilation scenario with no downloads of source code from external sources
- **Limited file system context** — while we see the compilation output, we don't see the source file (calc.cs) being read or accessed
- **No registry modifications** — the compilation process doesn't generate registry telemetry

The PowerShell channel contains only standard test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no actual compilation commands logged as script blocks.

## Assessment

This dataset provides excellent coverage for detecting T1027.004 via csc.exe compilation. The combination of Security 4688 and Sysmon 1 events delivers comprehensive command-line visibility, while Sysmon 11 events show the artifact creation. The process chain is clearly visible from PowerShell through cmd.exe to csc.exe, with the crucial command-line arguments preserved.

The data quality is strong for building detections around compiler abuse, suspicious compilation locations (Windows\Temp), and the characteristic cvtres.exe child process behavior. The Sysmon rule tagging correctly identifies both the trusted developer utility proxy execution (T1127) and the underlying technique.

For production detection engineering, this dataset supports both behavioral and contextual detection approaches, though it would benefit from examples of the compiled binary being executed to capture the full attack lifecycle.

## Detection Opportunities Present in This Data

1. **C# Compiler Execution Detection** — Monitor for csc.exe process creation, especially when parent processes are scripting engines (PowerShell, cmd.exe) rather than development tools

2. **Suspicious Compilation Output Paths** — Alert on csc.exe writing executables to temporary directories, system directories, or other non-development locations using the `/out:` parameter

3. **Compiler Child Process Anomalies** — Detect csc.exe spawning cvtres.exe outside of legitimate development environments or Visual Studio contexts

4. **PowerShell-to-Compiler Process Chain** — Monitor for PowerShell spawning cmd.exe that subsequently launches compilation tools

5. **Temporary File Creation by Compilers** — Track Sysmon EID 11 events where csc.exe creates .tmp files and executables in system temp directories

6. **Process Access Patterns** — Alert on PowerShell processes accessing compiler-related processes with high privileges (0x1FFFFF access)

7. **Compilation Command Line Indicators** — Parse csc.exe command lines for suspicious source file paths (AtomicRedTeam, temp directories) or output executable names
