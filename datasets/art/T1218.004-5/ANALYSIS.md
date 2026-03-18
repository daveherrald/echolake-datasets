# T1218.004-5: InstallUtil — InstallUtil Uninstall method call - /U variant

## Technique Context

T1218.004 (InstallUtil) is a defense evasion technique where attackers abuse Microsoft's legitimate InstallUtil.exe utility to execute malicious code. InstallUtil.exe is a command-line utility that comes with the .NET Framework and is designed to install and uninstall server resources by executing installer components in specified assemblies. Attackers exploit this by creating malicious .NET assemblies that contain code in their constructors or install/uninstall methods, which gets executed when InstallUtil processes the assembly.

The detection community focuses on monitoring InstallUtil.exe execution, especially with unusual command-line arguments, execution from unexpected locations, or processing of assemblies from suspicious paths. The `/U` (uninstall) variant is particularly notable because it executes the Uninstall method in addition to the constructor, providing attackers with multiple execution vectors. Key detection opportunities include process creation events for InstallUtil.exe, file creation of suspicious assemblies, and the compilation activities that often precede InstallUtil abuse.

## What This Dataset Contains

This dataset captures a complete InstallUtil execution chain using the `/U` (uninstall) variant. The data shows PowerShell (PID 39344) first compiling a malicious .NET assembly using the C# compiler (csc.exe), then executing it via InstallUtil.exe.

Security event 4688 captures the key InstallUtil execution: `"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe" /logfile= /logtoconsole=false /U C:\Windows\TEMP\T1218.004.dll`. The `/U` flag indicates uninstall mode, `/logfile=` suppresses log output, and `/logtoconsole=false` prevents console output.

The compilation phase is well-documented with multiple Security 4688 events showing csc.exe execution: `"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Windows\SystemTemp\z5hbhk1g\z5hbhk1g.cmdline"` followed by cvtres.exe for resource compilation.

Sysmon captures the process tree with EID 1 events, including the InstallUtil process creation with full command line visibility and proper parent-child relationships. EID 11 events show extensive file creation activity including the target DLL (`C:\Windows\Temp\T1218.004.dll`), temporary compilation files, and various supporting files in SystemTemp directories.

PowerShell script block logging (EID 4104) reveals the test framework code that builds and invokes the InstallUtil assembly, including the specific command line construction and expected output validation.

## What This Dataset Does Not Contain

The dataset lacks network telemetry that might show InstallUtil downloading assemblies from remote sources, which is a common attack vector. There are no registry modifications captured, though InstallUtil can interact with the registry during legitimate installation operations.

The Sysmon configuration's include-mode filtering for ProcessCreate means some child processes or related system activity may not be captured if they don't match the known-suspicious patterns. However, the key processes (InstallUtil, csc.exe, cvtres.exe) are all present, indicating good coverage for this technique.

Windows Defender appears fully active but does not block this execution, which is expected since this represents legitimate use of signed Microsoft utilities with a test assembly rather than actual malware.

## Assessment

This dataset provides excellent telemetry for InstallUtil detection engineering. The Security audit logs capture the complete process execution chain with full command lines, making it easy to identify the characteristic patterns of InstallUtil abuse. The combination of compilation activity (csc.exe) followed by InstallUtil execution provides a strong behavioral signature.

Sysmon data adds valuable context with process trees, file creation events, and image load information. The PowerShell logging reveals the orchestration logic, which helps analysts understand the complete attack flow. The presence of both the compilation phase and the InstallUtil execution phase makes this dataset particularly valuable for developing behavioral detections that look for these activities in sequence.

The clean execution (exit code 0x0 for all processes) and the `/U` variant usage make this dataset representative of real-world InstallUtil abuse scenarios.

## Detection Opportunities Present in This Data

1. InstallUtil.exe process creation with command-line arguments, especially the `/U` flag for uninstall operations and log suppression flags (`/logfile=`, `/logtoconsole=false`)

2. C# compiler (csc.exe) execution followed by InstallUtil.exe execution within a short time window, indicating on-the-fly assembly compilation and execution

3. File creation events for .NET assemblies in temporary directories (like `C:\Windows\TEMP\T1218.004.dll`) followed by InstallUtil processing those same files

4. PowerShell script execution that contains InstallUtil-related strings, particularly the InstallHelper method calls or assembly compilation code

5. Process tree analysis showing PowerShell spawning csc.exe and InstallUtil.exe in sequence, which is unusual for legitimate software installations

6. InstallUtil execution from standard .NET Framework directories but processing assemblies from non-standard locations like user temp directories

7. cvtres.exe activity in conjunction with csc.exe compilation, indicating dynamic .NET assembly creation preceding InstallUtil execution
