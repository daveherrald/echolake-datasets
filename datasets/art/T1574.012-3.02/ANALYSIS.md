# T1574.012-3: COR_PROFILER — Registry-free Process Scope COR_PROFILER

## Technique Context

T1574.012 (Hijack Execution Flow: COR_PROFILER) abuses the .NET CLR profiling API to inject code into managed processes. Unlike the system-scope (T1574.012-2) or user-scope registry variants, the **registry-free process-scope** approach sets the three CLR profiler environment variables (`COR_ENABLE_PROFILING`, `COR_PROFILER`, `COR_PROFILER_PATH`) directly in the current PowerShell session using the `$env:` syntax, then spawns a child process that inherits those variables. The child process — itself a .NET host — loads the profiler DLL before any managed code runs.

This variant is notable from a detection standpoint because it leaves **no registry artifacts at all**. The variables exist only in the memory of the PowerShell process that set them and in any child processes it spawns. When the parent process exits, the injection opportunity disappears without a trace in the registry. Detection must rely entirely on process-level telemetry.

## What This Dataset Contains

The dataset captures 117 events across three log sources: PowerShell (103 events: 100 EID 4104, 3 EID 4103), Security (13 events: 7 EID 4689, 5 EID 4688, 1 EID 4703), and Application (1 event: EID 1022). All events were collected on ACME-WS06 (Windows 11 Enterprise, domain-joined, Defender disabled).

**The environment variable injection and child process spawn are captured in Security EID 4688.** PowerShell spawned a child PowerShell process with:

```
"powershell.exe" & {$env:COR_ENABLE_PROFILING = 1
$env:COR_PROFILER = '{09108e71-974c-4010-89cb-acf471ae9e2c}'
$env:COR_PROFILER_PATH = '"C:\AtomicRedTeam\atomics\T1574.012\bin\T1574.012x64.dll"'
POWERSHELL -c 'Start-Sleep 1'}
```

This command sets all three profiler variables in the child PowerShell session's environment and then spawns a grandchild `POWERSHELL -c 'Start-Sleep 1'` — a .NET host that will inherit the environment and load the profiler DLL before executing `Start-Sleep`. The grandchild process is also captured in EID 4688:

```
New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process Command Line: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "Start-Sleep 1"
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**Application EID 1022 confirms the profiler DLL failed to load:**

```
.NET Runtime version 4.0.30319.0 - Loading profiler failed during CoCreateInstance.
Profiler CLSID: '{09108e71-974c-4010-89cb-acf471ae9e2c}'.
HRESULT: 0x8007007e.
Process ID (decimal): 15520.
```

`HRESULT 0x8007007e` is `ERROR_MOD_NOT_FOUND` — the DLL file at the specified path was not found or could not be loaded. This indicates that `T1574.012x64.dll` was either not present at the specified path on this machine, or could not be loaded by the CLR for the grandchild PowerShell process.

The cleanup phase is captured in EID 4688:

```
"powershell.exe" & {$env:COR_ENABLE_PROFILING = 0
$env:COR_PROFILER = ''
$env:COR_PROFILER_PATH = ''}
```

PowerShell EID 4104 captures the cleanup scriptblock:

```
& {$env:COR_ENABLE_PROFILING = 0
$env:COR_PROFILER = ''
$env:COR_PROFILER_PATH = ''}
```

Security EID 4703 records the parent PowerShell (PID 0x447c) receiving elevated privileges consistent with SYSTEM execution.

## What This Dataset Does Not Contain

**The profiler DLL did not load.** Application EID 1022 explicitly confirms that `CoCreateInstance` failed for CLSID `{09108e71-974c-4010-89cb-acf471ae9e2c}` with `ERROR_MOD_NOT_FOUND`. No profiler code executed in the `Start-Sleep 1` target process. This test did not succeed in injecting code.

**No Sysmon events are present.** Without Sysmon EID 7 (Image Loaded), you cannot observe whether any DLL at all was loaded before the failure. Without Sysmon EID 1 (Process Create with hashes), you have no hash-level identification of the grandchild PowerShell process.

**No registry artifacts.** By design, this variant writes nothing to the registry. The `HKCU` and `HKLM` environment paths are untouched — the only record of the variable assignments is in the EID 4688 command lines.

## Assessment

The defended variant recorded 58 Sysmon, 12 Security, 40 PowerShell, and 1 Application event. The Sysmon events in that run would have included EID 1 for the grandchild process and potentially EID 7 showing the failed load attempt. The undefended run produced 0 Sysmon, 13 Security, and 103 PowerShell events, plus the critical Application EID 1022.

The Application log entry is the most forensically significant event in this dataset — it provides a direct, system-generated record that the CLR attempted to load a profiler DLL, failed with `ERROR_MOD_NOT_FOUND`, and records the CLSID. This happens regardless of whether Sysmon or Defender is present; the .NET runtime logs this to the Windows Application Event Log automatically. Even in a detection-impoverished environment, this event would surface the attack attempt.

Compared to the system-scope variant (T1574.012-2), the process-scope approach leaves fewer artifacts — no registry writes — but the Application EID 1022 record is actually more explicit about the attack than any registry event would be.

## Detection Opportunities Present in This Data

**Application EID 1022 — .NET Runtime profiler load failure.** This event fires whenever a process attempts to load a COR_PROFILER DLL and fails. It records the CLSID and the affected process ID. Even a failed injection attempt is fully documented here. In a successful attack, you would see the profiler load — but in Windows 10/11 environments, a successful load does not generate an Application log event by default, making EID 1022 valuable specifically for catching failed attempts that reveal the CLSID and path.

**EID 4688 — PowerShell spawning a child PowerShell with `$env:COR_ENABLE_PROFILING` and `$env:COR_PROFILER` set in the command line.** The full environment variable assignments with the CLSID and DLL path appear in the process command line. This is the primary detection point for this variant — the inherited environment is visible in the parent's launch command, not in the child's.

**EID 4688 — PowerShell -c 'Start-Sleep 1' spawned by a PowerShell process.** A grandchild `powershell.exe` launched with `-c 'Start-Sleep 1'` from a parent PowerShell is an unusual pattern. Legitimate code rarely needs to launch a child PowerShell just to sleep. Combined with the parent's environment variable setup, this is immediately suspicious.

**EID 4688 — Cleanup of `$env:COR_*` variables from a scripted context.** Resetting the profiler variables to zero and empty strings immediately after the injection attempt is cleanup behavior consistent with post-exploitation tradecraft.
