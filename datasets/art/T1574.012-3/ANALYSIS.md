# T1574.012-3: COR_PROFILER — Registry-free Process Scope COR_PROFILER

## Technique Context

T1574.012 (COR_PROFILER) abuses the .NET CLR profiling API to inject an attacker-controlled DLL into managed processes. Unlike the system-scope or user-scope registry variants, the **registry-free process-scope** approach sets profiling environment variables (`COR_ENABLE_PROFILING`, `COR_PROFILER`, `COR_PROFILER_PATH`) directly in the current process's environment using PowerShell's `$env:` syntax, then spawns a child process — in this case a new `POWERSHELL` process — that inherits those variables and loads the profiler DLL before any managed code runs. This variant leaves no registry artifacts and operates entirely within process memory.

## What This Dataset Contains

The dataset spans roughly 10 seconds across four log sources (58 Sysmon events, 12 Security events, 40 PowerShell events, 1 Application event).

**PowerShell Event 4104** captures the complete attack payload across two script block recordings:

```
$env:COR_ENABLE_PROFILING = 1
$env:COR_PROFILER = '{09108e71-974c-4010-89cb-acf471ae9e2c}'
$env:COR_PROFILER_PATH = '"C:\AtomicRedTeam\atomics\T1574.012\bin\T1574.012x64.dll"'
POWERSHELL -c 'Start-Sleep 1'
```

The child PowerShell process (`Start-Sleep 1`) is the victim process that inherits the profiling environment and would load the DLL.

**Application Event 1022** from the .NET Runtime reveals the profiler load failure:
```
.NET Runtime version 4.0.30319.0 - Loading profiler failed during CoCreateInstance.
Profiler CLSID: '{09108e71-974c-4010-89cb-acf471ae9e2c}'. HRESULT: 0x8007007e.
```
Error `0x8007007e` is `ERROR_MOD_NOT_FOUND` — the DLL does not exist at the specified path, so the CLR logged the failure. This event, sourced from the Application log, confirms the injection attempt was made by the child PowerShell process.

**Sysmon Event 1** (ProcessCreate) captures both the parent PowerShell process (the attacker's script) and the child `powershell.exe` spawned with `-c 'Start-Sleep 1'`, tagged `technique_id=T1059.001`. The `whoami.exe` call from the ART test framework also appears tagged `technique_id=T1033`.

**Sysmon Event 10** (ProcessAccess) fires on the parent PowerShell's cross-process access to the child, tagged `technique_id=T1055.001`.

**Sysmon Event 7** (ImageLoad) records .NET runtime DLLs (`mscoree.dll`, CLR JIT assemblies) loading into each new PowerShell process — consistent with CLR initialization and profiler attachment attempts.

**Security Event 4688** records three distinct process creation events: the test framework PowerShell, `whoami.exe`, and the child PowerShell victim process.

## What This Dataset Does Not Contain

Because the profiler DLL (`T1574.012x64.dll`) is absent from the filesystem, the injection fails and no Sysmon Event 7 for the attacker's DLL appears. There is no evidence of code execution within the profiler. No network connection or file write from the victim process is captured. Registry writes are absent because this variant is specifically registry-free. The Sysmon ProcessCreate filter is include-mode; only rule-matched process creations (PowerShell, LOLBins, whoami) appear.

## Assessment

This is the most forensically interesting of the COR_PROFILER variants for detection purposes: the registry-free approach is a common evasion strategy, yet the PowerShell script block logging faithfully records the environment variable assignments and child process invocation. The Application Event 1022 provides independent corroboration that the CLR attempted to load the profiler — this is telemetry that would appear even on systems without Sysmon or PowerShell logging. Defender was active but did not block the attempt; the failure was due to the missing DLL, not AV intervention.

## Detection Opportunities Present in This Data

- **PowerShell Event 4104**: Script blocks assigning `$env:COR_ENABLE_PROFILING`, `$env:COR_PROFILER`, or `$env:COR_PROFILER_PATH` in the same block that spawns a child process.
- **PowerShell Event 4103**: Module logging of `Start-Sleep` invoked from a PowerShell instance whose host application string contains COR profiling variable assignments.
- **Application Event 1022**: .NET Runtime errors with "Loading profiler failed" and a foreign CLSID — this fires regardless of profiler success or failure and does not require Sysmon.
- **Sysmon Event 1**: `powershell.exe` spawning a child `powershell.exe` within a very short window (sub-second) warrants scrutiny, especially where the parent's command line sets environment variables.
- **Sysmon Event 10**: Cross-process access from PowerShell to a child PowerShell process.
- Absence of registry writes distinguishes this variant from T1574.012 tests 1 and 2; detecting it requires process-level environment inspection (e.g., via Event 4104 or process memory analysis) rather than registry monitoring alone.
