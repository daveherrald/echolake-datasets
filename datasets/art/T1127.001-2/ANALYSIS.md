# T1127.001-2: MSBuild — VB

## Technique Context

T1127.001 (MSBuild) represents one of the most effective defense evasion techniques leveraging Microsoft's trusted build system. MSBuild.exe is a signed Microsoft binary that can compile and execute arbitrary .NET code through inline tasks in MSBuild project files. This technique is particularly valuable to attackers because MSBuild is present on most Windows systems, is digitally signed by Microsoft, and often whitelisted by application control solutions. The technique allows adversaries to execute arbitrary code while hiding behind a legitimate Microsoft process, making it difficult to distinguish from normal build activities.

The detection community focuses on unusual MSBuild executions, particularly those processing XML files from suspicious locations, invoking VBC/CSC compilers, and creating temporary files in system directories. This specific test demonstrates the VB.NET variant of the technique, where malicious Visual Basic code is embedded within MSBuild project XML and compiled at runtime.

## What This Dataset Contains

This dataset captures a complete MSBuild inline task execution chain. The Security channel shows the full process tree: PowerShell launches `cmd.exe /c C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe "C:\AtomicRedTeam\atomics\T1127.001\src\vb.xml"`, which spawns MSBuild.exe (PID 39092), followed by vbc.exe (PID 29728) and cvtres.exe (PID 33952) for compilation.

Sysmon captures critical detection artifacts including MSBuild process creation with CommandLine `C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe "C:\AtomicRedTeam\atomics\T1127.001\src\vb.xml"` and VBC.exe spawning with `"C:\Windows\Microsoft.NET\Framework\v4.0.30319\vbc.exe" /noconfig @"C:\Windows\SystemTemp\uw4zzupi\uw4zzupi.cmdline"`. Multiple EID 11 events show temporary file creation in `C:\Windows\SystemTemp\uw4zzupi\` including the compiled DLL `uw4zzupi.dll`. 

EID 29 confirms executable file detection for the compiled DLL with hash `SHA256=626A11810B6002C4CF1980B9A5DC11ACDFD85ADE5F06557AB9F45EFA57EE06D0`. EID 10 process access events show PowerShell and MSBuild accessing spawned child processes. EID 7 events capture AMSI and Windows Defender DLL loads in MSBuild, indicating security product interaction with the execution.

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without the actual technique payload.

## What This Dataset Does Not Contain

The dataset lacks evidence of the actual payload execution within the compiled DLL - we see compilation artifacts but no subsequent execution of the malicious code that would have been embedded in the VB inline task. The technique successfully compiled the malicious VB.NET code into a DLL but the telemetry doesn't capture what that compiled code actually did when executed by MSBuild.

There's no network activity, registry modifications, or other post-exploitation behaviors that would typically follow a successful MSBuild bypass. The dataset also doesn't show the content of the vb.xml file that contained the inline task definition, though the file path suggests it's part of the Atomic Red Team test structure.

No Windows Defender blocking events are present despite the DLL loads, indicating the technique bypassed real-time protection successfully.

## Assessment

This dataset provides excellent telemetry for detecting T1127.001 MSBuild abuse. The Security 4688 events capture the complete process chain with full command lines, while Sysmon adds crucial file creation artifacts and process relationships. The combination of MSBuild spawning VBC.exe, temporary file creation patterns, and executable detection events provides multiple detection points.

The data quality is high for building behavioral detections around MSBuild abuse patterns. However, the dataset would be strengthened by capturing the payload execution phase and any subsequent malicious activities performed by the compiled code.

## Detection Opportunities Present in This Data

1. MSBuild.exe execution with XML file arguments, especially from non-standard locations like AtomicRedTeam directories (Security 4688, Sysmon 1)

2. MSBuild spawning compiler processes (vbc.exe, csc.exe) as child processes - unusual for legitimate build scenarios (Security 4688 parent-child relationships)

3. Temporary file creation in system directories (`C:\Windows\SystemTemp\`) by MSBuild processes (Sysmon 11)

4. MSBuild creating executable files (.dll, .exe) in temporary locations (Sysmon 29 File Executable Detected)

5. Process access patterns where MSBuild accesses spawned compiler processes (Sysmon 10)

6. VBC.exe execution with response files (@filename syntax) containing compilation parameters (Security 4688)

7. MSBuild loading AMSI/security product DLLs indicating potential evasion attempts (Sysmon 7)

8. Correlation of MSBuild execution with immediate compiler spawning and DLL generation in rapid succession
