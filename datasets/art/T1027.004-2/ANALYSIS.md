# T1027.004-2: Compile After Delivery — Dynamic C# Compile

## Technique Context

T1027.004 (Compile After Delivery) involves adversaries delivering source code to target systems and compiling it locally to avoid static analysis detection. This technique is particularly effective because source code can bypass signature-based detections and appear benign during transport. Dynamic C# compilation is a popular variant where C# source code is compiled at runtime using the .NET framework's built-in compilation capabilities (CSharpCodeProvider, CodeDOM, or newer Roslyn APIs).

Attackers leverage this technique to:
- Evade static analysis tools that scan for compiled executables
- Bypass application whitelisting that permits trusted compilers like csc.exe
- Deliver payloads as seemingly innocuous text files
- Implement just-in-time compilation for modular malware

The detection community focuses on monitoring compilation processes, .NET runtime loading patterns, and the creation of temporary assemblies. Key indicators include the loading of compiler-related DLLs (mscoreei.dll, clr.dll), process creation patterns involving development tools, and file system artifacts from compilation activities.

## What This Dataset Contains

This dataset captures the execution of a pre-compiled test executable (`T1027.004_DynamicCompile.exe`) rather than actual source code compilation. The security events reveal the complete process chain:

1. **Initial PowerShell execution** (Security 4688): `powershell.exe` with command line `& {Invoke-Expression \"C:\AtomicRedTeam\atomics\T1027.004\bin\T1027.004_DynamicCompile.exe\"}`
2. **Test executable launch** (Security 4688): `C:\AtomicRedTeam\atomics\T1027.004\bin\T1027.004_DynamicCompile.exe`
3. **Fondue.exe spawning** (Security 4688): `"C:\Windows\system32\fondue.exe" /enable-feature:NetFx3 /caller-name:mscoreei.dll`

The Sysmon telemetry shows extensive .NET framework loading activity:
- **CLR initialization** (Sysmon EID 7): Loading of `mscoree.dll`, `mscoreei.dll`, `clr.dll`, and `clrjit.dll`
- **PowerShell automation loading**: `System.Management.Automation.ni.dll` in multiple PowerShell processes
- **Process access events** (Sysmon EID 10): PowerShell accessing child processes with full access rights (0x1FFFFF)

The executable appears to fail with exit status `0x80131700` (a .NET runtime exception), and Fondue.exe fails with `0x80004005` (generic COM error), suggesting the dynamic compilation attempt encountered errors.

## What This Dataset Does Not Contain

This dataset lacks the actual source code compilation artifacts that would characterize a true T1027.004 execution:

- **No compiler process creation**: Missing csc.exe, vbc.exe, or other .NET compiler processes that would indicate real-time compilation
- **No source code files**: Absent are .cs files or other source code artifacts being read from disk
- **Limited compilation DLL loading**: While .NET runtime DLLs are loaded, compiler-specific DLLs (System.CodeDom.dll, Microsoft.CSharp.dll) are not observed
- **No temporary assembly creation**: Missing file creation events for dynamically compiled assemblies typically written to %TEMP% or GAC

The PowerShell script block logging contains mostly test framework boilerplate (`Set-StrictMode`, error handling scriptblocks) rather than actual compilation code. The technique appears to have failed during execution, preventing observation of successful dynamic compilation telemetry.

## Assessment

This dataset provides limited utility for detecting actual T1027.004 dynamic compilation attacks. While it captures the .NET runtime initialization patterns common to .NET applications, it lacks the specific compilation process telemetry that distinguishes dynamic compilation from normal .NET application execution.

The process tree and .NET DLL loading patterns could be useful for establishing baseline .NET application behavior, but defenders would need additional datasets showing successful dynamic compilation to build effective detections. The failure artifacts (exit codes, Fondue.exe spawning) may actually represent environmental issues rather than technique-specific behaviors.

For detection engineering, this data is more valuable as a negative example showing what insufficient telemetry looks like when T1027.004 attempts fail early in execution.

## Detection Opportunities Present in This Data

1. **Suspicious PowerShell command patterns**: Monitor for PowerShell executing external binaries via `Invoke-Expression` with file paths containing "atomics" or test frameworks

2. **Fondue.exe anomalous spawning**: Alert on fondue.exe execution with `/caller-name:mscoreei.dll` parameter, especially when spawned by non-system processes

3. **.NET runtime loading sequence**: Detect rapid sequential loading of core .NET DLLs (mscoree.dll → mscoreei.dll → clr.dll → clrjit.dll) in suspicious processes

4. **Process access patterns**: Monitor for PowerShell processes accessing recently spawned executables with full access rights (0x1FFFFF)

5. **Executable failure correlation**: Correlate process creation events with immediate exit status failures (0x80131700) in .NET applications as potential compilation attempt indicators

6. **PowerShell pipe creation patterns**: Track PowerShell processes creating named pipes with specific naming conventions that may indicate automation framework usage
