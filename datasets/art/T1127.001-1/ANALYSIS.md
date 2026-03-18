# T1127.001-1: MSBuild — C#

## Technique Context

T1127.001 (MSBuild) represents a defense evasion technique where attackers abuse Microsoft's MSBuild.exe, a legitimate Windows build utility, to execute malicious code while appearing as a trusted process. This technique is particularly valuable to attackers because MSBuild.exe is a signed Microsoft binary that's commonly found in enterprise environments and rarely blocked by application whitelisting solutions.

The "inline tasks" variant leverages MSBuild's capability to execute C# code directly within project files through the `<UsingTask>` and `<Task>` XML elements. This allows attackers to embed arbitrary .NET code in seemingly innocent build files, bypassing many detection mechanisms that focus on traditional executable file drops. The detection community focuses on monitoring MSBuild execution outside of legitimate development contexts, unusual command-line arguments, and the compilation of temporary C# files in system directories.

## What This Dataset Contains

This dataset captures a successful MSBuild inline task execution with excellent telemetry coverage across all major Windows logging sources. The attack chain begins with PowerShell (PID 14872) spawning cmd.exe, which then executes MSBuild.exe with the command line: `C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe "C:\AtomicRedTeam\atomics\T1127.001\src\T1127.001.csproj"`.

Security event 4688 shows the complete process chain: PowerShell → cmd.exe → MSBuild.exe → csc.exe (twice) → cvtres.exe (twice). The MSBuild process (PID 44460) creates temporary directories and files in `C:\Windows\SystemTemp\` with randomized names like "314uadda" and "dccwfiex", typical behavior for MSBuild compilation operations.

Sysmon EID 1 events capture MSBuild.exe execution with RuleName "technique_id=T1127,technique_name=Trusted Developer Utilities Proxy Execution" and the subsequent C# compiler (csc.exe) invocations. Critical file creation events (Sysmon EID 11) show MSBuild writing `.cs`, `.dll`, `.cmdline`, `.pdb`, and temporary resource files to the SystemTemp directory, indicating successful code compilation.

The dataset also includes Sysmon EID 7 events showing AMSI.dll loading into the MSBuild process and multiple Windows Defender DLL loads (MpOAV.dll, MpClient.dll), demonstrating that security solutions were active but did not block the execution.

## What This Dataset Does Not Contain

The dataset lacks the actual malicious project file content that was executed, which would be critical for understanding the specific inline task payload. While file creation events show compilation artifacts, the source C# code within the .csproj file is not captured in the logs.

Notably absent are any blocking events or error codes that would indicate Defender intervention. All processes show clean exit status 0x0 in Security event 4689, suggesting the technique executed successfully without triggering behavioral blocking. The PowerShell channel contains only test framework boilerplate (Set-ExecutionPolicy Bypass), providing no insight into the actual malicious payload.

Network activity is also missing—if the inline task attempted outbound connections, they're not captured in this dataset's timeframe. Additionally, there are no registry modifications logged, though MSBuild inline tasks can certainly perform registry operations.

## Assessment

This dataset provides excellent detection engineering value for MSBuild abuse scenarios. The telemetry quality is outstanding, with complete process lineage, detailed command lines, file system artifacts, and precise timing across Security and Sysmon channels. The presence of both 32-bit and 64-bit .NET Framework tools (evidenced by different csc.exe and cvtres.exe executions) adds realistic complexity.

The dataset effectively demonstrates how MSBuild inline tasks appear in logs during normal security tool operation, making it particularly valuable for tuning detection rules to minimize false positives in development environments. The randomized temporary directory names and compilation artifacts provide realistic patterns for building robust detection logic.

## Detection Opportunities Present in This Data

1. **MSBuild execution outside development contexts** - Monitor Sysmon EID 1 for MSBuild.exe processes spawned from unexpected parents like PowerShell or cmd.exe rather than Visual Studio or build servers.

2. **Temporary compilation artifacts in system directories** - Alert on Sysmon EID 11 file creation events for .cs, .dll, and .cmdline files in `C:\Windows\SystemTemp\` by MSBuild processes.

3. **C# compiler invocation by MSBuild** - Detect Security EID 4688 or Sysmon EID 1 showing csc.exe spawned by MSBuild.exe, especially with `/noconfig` and response file (@) command-line patterns.

4. **MSBuild process lineage anomalies** - Build detection logic around Security EID 4688 showing MSBuild as a child of scripting engines (powershell.exe, cmd.exe, wscript.exe) rather than development tools.

5. **Rapid compilation sequence patterns** - Correlate multiple csc.exe and cvtres.exe executions within short timeframes as potential indicators of inline task compilation.

6. **MSBuild AMSI integration monitoring** - Track Sysmon EID 7 showing amsi.dll loading into MSBuild processes, which may indicate content scanning of inline tasks.

7. **Randomized temporary directory creation** - Monitor for MSBuild creating directories with random alphanumeric names in system temp locations via Sysmon EID 11 events.
