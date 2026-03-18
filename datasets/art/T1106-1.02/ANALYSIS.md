# T1106-1: Native API — Execution through API - CreateProcess

## Technique Context

T1106 (Native API) covers adversary use of Windows native APIs—functions exposed directly by the Windows kernel or core DLLs—to execute code, bypass higher-level monitoring, or perform operations that evade controls implemented at the Win32 API layer. `CreateProcess` is the canonical Win32 API for launching new processes, but the MITRE technique focuses on its use as a programmatic execution primitive rather than through normal application behaviors.

This test compiles a C# source file (`CreateProcess.cs`) at runtime using `csc.exe` (the .NET C# compiler), then executes the resulting binary. The compiled program calls `CreateProcess` to spawn a child process. This demonstrates a pattern used by adversaries and offensive tools to execute payloads via compiled-in-memory or on-disk code that invokes Windows APIs directly—bypassing PowerShell script controls and relying on the compiler being present in the .NET framework installation.

The technique is particularly relevant in environments where PowerShell is constrained (Constrained Language Mode, AMSI, script block logging) but the .NET compiler tools are accessible.

## What This Dataset Contains

This dataset was collected on ACME-WS06, a Windows 11 Enterprise domain workstation with Microsoft Defender disabled. The compilation and execution completed fully.

**Process Chain (Security EID 4688 / Sysmon EID 1):**

The ART test framework PowerShell (PID 1132) spawns `cmd.exe` (PID 6776, tagged `technique_id=T1059.003`) with:

```
"cmd.exe" /c C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /out:"%tmp%\T1106.exe" /target:exe "C:\AtomicRedTeam\atomics\T1106\src\CreateProcess.cs" & %tmp%/T1106.exe
```

This single cmd.exe command does two things in sequence: first it compiles `CreateProcess.cs` to `%tmp%\T1106.exe` using `csc.exe`, then it executes the resulting binary. Both the compilation and execution are chained in one `cmd /c` call.

A second `cmd.exe` instance (PID 4828) appears with an empty command line `"cmd.exe" /c` at 23:46:28.111—this is the cleanup or trailing cmd invocation from the ART test framework.

**File Creation (Sysmon EID 11):**

Two file creation events capture PowerShell profile data writes:
- `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive` (PID 1132, the test framework PowerShell, at 23:46:28.489)
- `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MsMpEng.exe` creates `C:\Windows\Temp\01dcb40cc27b1f55` (the Defender housekeeping artifact)

Notably, the compiled `T1106.exe` binary does not appear in EID 11—it is written to `%tmp%` by `csc.exe` as part of the compilation, but that write was not captured in the Sysmon sample. The file would land at `C:\Windows\TEMP\T1106.exe`.

**Process Termination (Sysmon EID 5):**

One process termination event appears in the dataset (EID 5 count: 1 in the sysmon breakdown), likely corresponding to the exit of one of the short-lived child processes (whoami.exe, cmd.exe, or T1106.exe itself).

**Image Loads (Sysmon EID 7):**

Sixteen DLL load events for the test framework PowerShell (PID 1132).

**Process Access (Sysmon EID 10):**

Five process access events show PID 1132 (PowerShell) accessing `whoami.exe` (PID 6640, PID 1644) and `cmd.exe` (PID 6776) with `GrantedAccess: 0x1FFFFF`.

**Named Pipe (Sysmon EID 17):**

`\PSHost.134180055806394175.1132.DefaultAppDomain.powershell` (PID 1132).

**PowerShell Script Block Logging (EID 4104/4103):**

105 events: 103 EID 4104 script blocks, 2 EID 4103 pipeline execution events. The higher count compared to other T1105 tests reflects additional code paths in the T1106 ART module.

**Application Log (EID 15):**

Two EID 15 events from Windows Security Center—Defender status updates, consistent with the test sequence.

## What This Dataset Does Not Contain

The compiled `T1106.exe` binary does not appear as an EID 1 process creation in the Sysmon sample set—the compilation and execution occurred within the cmd.exe `& ` chain, and the EID 1 for T1106.exe and csc.exe were not included in the 15-event sample. You can infer their execution from the cmd.exe command line, but you do not have direct Sysmon EID 1 evidence of `csc.exe` or `T1106.exe` in this sample.

The `CreateProcess` API call made by `T1106.exe` to spawn its child process is not directly logged—there is no "API call" event type in Sysmon or Windows event logs. You see the outcome (a child process) but not the API invocation itself.

The C# source code at `CreateProcess.cs` is not logged or readable from this dataset. No file creation event captures the `T1106.exe` binary landing in `%TEMP%`.

## Assessment

This dataset's primary value is the cmd.exe command line showing runtime compilation followed by execution: `csc.exe /out:%tmp%\T1106.exe /target:exe <source.cs> & %tmp%/T1106.exe`. This pattern—compile from source, immediately execute—is a strong behavioral indicator because it collapses the typical payload delivery step. An adversary would use a similar pattern to convert C# source (perhaps delivered as an obfuscated string or downloaded file) into an executable that invokes Windows APIs.

Compared to the defended variant (sysmon 32, security 21, powershell 27), the undefended dataset has more events across all channels (sysmon 36, security 9, powershell 105). The much larger difference in PowerShell event counts (105 vs. 27) reflects that Defender's presence in the defended variant triggers rapid remediation, cutting the ART test framework execution short and reducing logged script block activity.

## Detection Opportunities Present in This Data

**Runtime compilation to %TEMP% (EID 4688 / EID 1):** `csc.exe /out:%tmp%\<name>.exe /target:exe <source.cs>` is a high-fidelity indicator of in-place compilation for execution. Legitimate software does not compile C# source files to `%TEMP%` at runtime. The specific pattern `cmd.exe /c csc.exe ... & <compiled>.exe` is even more specific—compile and immediately run.

**cmd.exe spawning csc.exe:** `csc.exe` spawned by `cmd.exe` (rather than by a build system or IDE) is anomalous. The parent process `cmd.exe` with a compiler child is worth alerting on in most enterprise environments.

**Sysmon rule tag T1059.003:** The cmd.exe invocation is tagged by Sysmon's built-in ruleset as Windows Command Shell abuse.

**Short-lived executable in %TEMP%:** If endpoint filesystem monitoring captures the creation of a `.exe` file in `%TEMP%` (C:\Windows\TEMP\T1106.exe), followed immediately by its execution, the sequence is definitive regardless of the filename.
