# T1127-1: Trusted Developer Utilities Proxy Execution — Lolbin Jsc.exe compile javascript to exe

## Technique Context

T1127 (Trusted Developer Utilities Proxy Execution) involves adversaries using legitimate developer and system administration utilities to execute malicious code while evading defenses. The jsc.exe (JScript .NET Compiler) utility is a particularly effective LOLBin because it can compile JavaScript code into executable files, allowing attackers to transform scripts into standalone binaries that may bypass script-blocking policies or static analysis tools. This technique is valuable for defense evasion because the compilation process uses a signed Microsoft utility, making the activity appear legitimate. The detection community focuses on monitoring for unusual usage of developer utilities like jsc.exe, especially when compiling user-supplied scripts or when executed from unusual locations or contexts.

## What This Dataset Contains

This dataset captures a successful jsc.exe compilation attack executed through PowerShell. The key evidence includes:

**Process chain captured in Sysmon and Security logs:**
- PowerShell → cmd.exe → jsc.exe → cvtres.exe (resource converter)
- Command line: `"cmd.exe" /c copy "C:\AtomicRedTeam\atomics\T1127\src\hello.js" %TEMP%\hello.js & C:\Windows\Microsoft.NET\Framework\v4.0.30319\jsc.exe %TEMP%\hello.js`
- jsc.exe execution: `C:\Windows\Microsoft.NET\Framework\v4.0.30319\jsc.exe C:\Windows\TEMP\hello.js`

**File operations in Sysmon Event ID 11:**
- JavaScript file copied: `C:\Windows\Temp\hello.js`
- Compiled executable created: `C:\Windows\Temp\hello.exe`
- Temporary resource files: `C:\Windows\SystemTemp\RES353A.tmp` and `C:\Windows\SystemTemp\RES353B.tmp`

**Process creation events showing the full attack flow:**
- Sysmon EID 1 for jsc.exe with rule match for T1127
- Security EID 4688 events with complete command lines
- cvtres.exe spawned by jsc.exe for resource conversion

The PowerShell channel contains only standard test framework boilerplate (`Set-ExecutionPolicy Bypass` and error handling scriptblocks), providing no technique-specific evidence.

## What This Dataset Does Not Contain

This dataset does not contain execution of the compiled hello.exe binary itself — the test only demonstrates the compilation phase. Additionally, there are no Sysmon ProcessCreate events for cmd.exe or cvtres.exe due to the include-mode filtering in the sysmon-modular configuration, though these processes are fully captured in Security 4688 events. The dataset also lacks any network connections, registry modifications, or additional file system artifacts that might occur during execution of the compiled binary.

## Assessment

This dataset provides excellent coverage for detecting T1127.001 jsc.exe abuse. The combination of Sysmon and Security event logs captures the complete attack chain with high-fidelity command lines, file creation events, and process relationships. The Sysmon rule specifically identifies jsc.exe execution as T1127, demonstrating that well-configured detection systems can effectively identify this technique. The Security 4688 events provide comprehensive process creation coverage that compensates for any gaps in Sysmon's filtered configuration. This data would be highly effective for building detections around jsc.exe usage patterns, suspicious JavaScript compilation, and the characteristic file artifacts created during the compilation process.

## Detection Opportunities Present in This Data

1. **jsc.exe process creation with user-supplied script arguments** - Monitor Security EID 4688 or Sysmon EID 1 for jsc.exe execution with command lines containing temporary directories or non-standard script paths.

2. **JavaScript file creation followed by immediate jsc.exe compilation** - Correlate Sysmon EID 11 file creation events for .js files with subsequent jsc.exe process creation targeting those same files.

3. **PowerShell spawning cmd.exe with jsc.exe in command line** - Detect PowerShell processes launching cmd.exe with command lines containing paths to .NET Framework jsc.exe.

4. **Executable file creation by jsc.exe in temporary directories** - Monitor Sysmon EID 11 for .exe file creation by jsc.exe processes, particularly in user-writable locations like %TEMP%.

5. **cvtres.exe spawned by jsc.exe** - Track parent-child relationships where cvtres.exe is spawned by jsc.exe, indicating active compilation activity.

6. **jsc.exe execution from unexpected parent processes** - Alert on jsc.exe launched by processes other than typical development tools like Visual Studio or MSBuild.

7. **Rapid sequence of copy operation followed by jsc.exe compilation** - Detect patterns where files are copied to temporary locations and immediately compiled using jsc.exe within a short time window.
