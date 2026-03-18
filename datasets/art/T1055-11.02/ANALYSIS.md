# T1055-11: Process Injection — Process Injection with Go using CreateThread WinAPI

## Technique Context

T1055 Process Injection describes a broad category of techniques where adversaries introduce code into the memory space of a running process and execute it there. By executing within a legitimate process, the injected code inherits that process's security context and can evade process-level defenses that focus on executable identity rather than memory content. The `CreateThread` variant is one of the simpler injection patterns: allocate memory in the target process, write shellcode or a DLL, then create a remote thread pointing at the injected code.

What distinguishes this particular test is the use of a Go-compiled binary (`CreateThread.exe`) rather than the more common .NET or PowerShell implementations. Go produces large, statically-linked executables with no runtime dependency on the .NET CLR. This means the injector does not generate .NET image-load telemetry when it runs — a meaningful difference from PowerShell-based or C# injectors that leave a trail of CLR DLL loads. Go binaries also resist string-based signature detection because Go's runtime mixes code and symbol data, and many Go malware families use identifier obfuscation. The increasing adoption of Go in offensive tooling (Sliver, Merlin, and others) makes this variant particularly relevant.

Detection for CreateThread-based injection centers on Sysmon EID 8 (CreateRemoteThread), process access events with high-privilege access masks, and behavioral analysis of the injector process itself. Because Go binaries don't trigger CLR-related image-load heuristics, behavioral telemetry from Sysmon EID 8 and EID 10 becomes the primary visibility layer.

## What This Dataset Contains

With Defender disabled, the Go injection binary executes without interference. The dataset captures the surrounding process activity but reveals a key limitation in the Sysmon configuration's process creation filtering.

**Security EID 4688 — process creation (4 events):** Two pairs document the test execution. The critical entry shows a child `powershell.exe` created with the command:

```
"powershell.exe" & {C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateThread.exe -debug}
```

The `-debug` flag suggests the binary provides verbose output during execution. A cleanup command `Stop-Process -Name CalculatorApp -ErrorAction SilentlyContinue` runs afterward, indicating the injection target is Calculator. Both run as `NT AUTHORITY\SYSTEM`.

**Sysmon EID 7 — image load (22 events):** .NET CLR components load into the orchestrating PowerShell processes: `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `clrjit.dll`. Windows Defender components `MpOAV.dll` and `MpClient.dll` also load. Notably, no image-load events from `CreateThread.exe` itself appear — because it is a Go binary, it loads no .NET DLLs and none of its imports trigger the sysmon-modular image-load rules.

**Sysmon EID 10 — process access (4 events):** PowerShell opening `whoami.exe` and a child `powershell.exe` with `GrantedAccess: 0x1fffff`, tagged `technique_id=T1055.001`. These are ART test framework artifacts (the test framework's own process management), not artifacts of the Go injection tool's target access.

**Sysmon EID 1 — process create (4 events):** `whoami.exe` (twice, tagged `T1033`) and the child PowerShell command (tagged `T1059.001`). `CreateThread.exe` itself does not appear in any Sysmon EID 1 event — it is a child of the PowerShell process and does not match the include-mode filter patterns.

**Sysmon EID 17 — named pipe create (3 events):** Three PowerShell host pipes created across the test's two execution phases.

**Sysmon EID 11 — file create (1 event):** PowerShell startup profile, standard artifact.

**PowerShell EID 4104 (103 events):** Entirely ART test framework boilerplate. The Go binary executes outside PowerShell's script execution context, so no script block captures its behavior.

**Comparison to the defended dataset:** The defended version recorded 36 sysmon, 10 security, and 45 powershell events — nearly identical totals to the undefended dataset (34 sysmon, 4 security, 103 powershell). The very similar Sysmon counts suggest that even with Defender enabled, the core Sysmon telemetry profile is similar. The defended dataset had more security events, likely from Defender's own process activity. The absence of Sysmon EID 8 (CreateRemoteThread) in the undefended dataset is notable — if the Go injection tool did create a remote thread, it was not captured by Sysmon's EID 8 monitoring for this execution.

## What This Dataset Does Not Contain

The dataset lacks any direct evidence of the injection activity itself:

- No Sysmon EID 8 (CreateRemoteThread) events. Either `CreateThread.exe` did not successfully reach the thread-creation phase, or the Sysmon config's EID 8 filter did not match the call signature.
- No Sysmon EID 1 for `CreateThread.exe`. The Go binary's process creation is invisible in Sysmon, making it impossible to determine its PID, hash, or whether it spawned any child processes.
- No evidence of the Calculator injection target (`CalculatorApp`). No process creation, no memory access from the injector to Calculator's process space.
- No Sysmon EID 3 (NetworkConnect) events. Go injection tools sometimes phone home after successful injection; none appear here.
- No image load artifacts from the Go runtime. This is structurally expected and is part of what makes Go injection tools harder to detect through DLL-load monitoring.

## Assessment

This dataset has limited value for building behavioral detections of the injection activity itself. The injector process is nearly invisible in the available telemetry. The primary value lies in the command-line visibility provided by Security EID 4688 and the correlation between PowerShell process creation and the `Stop-Process -Name CalculatorApp` cleanup command, which implies prior injection into Calculator. For defenders building detections against the Go injection binary specifically, this dataset demonstrates the Sysmon blind spots created by include-mode ProcessCreate filtering when applied to non-LOLBin executables. Expanding the Sysmon configuration to capture all process creations (or specifically covering binaries in `C:\AtomicRedTeam\`) would materially improve the telemetry.

## Detection Opportunities Present in This Data

1. Security EID 4688 `CommandLine` containing `CreateThread.exe -debug` — the path `C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateThread.exe` is an absolute indicator in a test environment; in production, look for unsigned Go binaries in unusual directories being executed by PowerShell.

2. The `Stop-Process -Name CalculatorApp` cleanup command in a subsequent `powershell.exe` process creation implies prior injection into Calculator — a process with no legitimate reason to be created and immediately killed in a SYSTEM context.

3. Sysmon EID 10 with `GrantedAccess: 0x1fffff` from PowerShell to child processes, combined with the parent PowerShell's command line containing a known injection tool, provides a multi-event correlation signal.

4. In environments with broader Sysmon ProcessCreate coverage, a Go binary (`CreateThread.exe`) launched from PowerShell as `NT AUTHORITY\SYSTEM` from `C:\Windows\TEMP\` would be the primary detection anchor. The absence of CLR-related image loads following this process creation distinguishes Go tools from .NET tools.

5. The three named pipe creation events (`\PSHost.*.DefaultAppDomain.powershell`) establish a process lifecycle timeline. Three pipes across a short window indicate three distinct PowerShell instances — correlating these with the corresponding EID 4688 events helps reconstruct the execution sequence even without direct injection artifacts.

6. Sysmon EID 17 named pipe creation combined with an absence of EID 8 (CreateRemoteThread) in a test purportedly performing thread injection is a detection gap indicator: the absence of the expected event type signals that either the technique failed or the monitoring configuration needs expansion.
