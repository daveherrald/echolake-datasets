# T1574.012-1: COR_PROFILER — COR_PROFILER - User scope COR_PROFILER

## Technique Context

T1574.012 (Hijack Execution Flow: COR_PROFILER) abuses the .NET Common Language Runtime (CLR) profiling API. When the environment variables `COR_ENABLE_PROFILING=1` and `COR_PROFILER={CLSID}` are set, the CLR loads the DLL registered under the given CLSID in the registry before executing any .NET application. An attacker who sets these variables — either in the process environment, the user's environment registry hive, or the system environment — causes their profiling DLL to load into every .NET process that starts under the affected scope.

This test configures COR_PROFILER at user scope by writing to `HKU\.DEFAULT\Environment`, registering a CLSID in `HKU\.DEFAULT\Software\Classes\CLSID\`, and pointing both to a pre-built ART test DLL.

## What This Dataset Contains

The dataset captures 79 events across Sysmon (37), Security (13), and PowerShell (29) logs collected over approximately 5 seconds on ACME-WS02.

**The full COR_PROFILER configuration is captured:**

Sysmon Event 13 (Registry Value Set) records all four registry writes that configure the profiler:
- `HKU\.DEFAULT\Software\Classes\CLSID\{09108e71-974c-4010-89cb-acf471ae9e2c}\InprocServer32\(Default)` — `C:\AtomicRedTeam\atomics\T1574.012\bin\T1574.012x64.dll`
- `HKU\.DEFAULT\Environment\COR_ENABLE_PROFILING` — `1`
- `HKU\.DEFAULT\Environment\COR_PROFILER_PATH` — `C:\AtomicRedTeam\atomics\T1574.012\bin\T1574.012x64.dll`
- `HKU\.DEFAULT\Environment\COR_PROFILER` — `{09108e71-974c-4010-89cb-acf471ae9e2c}`

Sysmon Event 1 shows the attack commands:
- `"powershell.exe" & {Write-Host "Creating registry keys in HKCU:Software\Classes\CLSID\{09108e71-974c-4010-89cb-acf471ae9e2c}"...}` — the attack script creating the CLSID registration and environment variables

Sysmon Event 10 (Process Access) shows:
- `powershell.exe` self-accessing `powershell.exe` — parent test framework spawning the attack child process
- `powershell.exe` accessing `whoami.exe` — identity check

PowerShell Event 4104 (Script Block Logging) captures the attack script:
- `& {Write-Host "Creating registry keys in HKCU:Software\Classes\CLSID\{09108e71-974c-4010-89cb-acf471ae9e2c}"...New-Item -Path "HKCU:\Software\Classes\CLSID\..."}` — full script content

Sysmon Event 11 (File Created) records PowerShell startup profile data — routine .NET CLR initialization artifacts.

## What This Dataset Does Not Contain (and Why)

**The COR_PROFILER DLL was not loaded.** The registry keys and environment variables were written successfully, but no subsequent .NET application was launched to trigger the profiler load. No Sysmon Event 7 showing `T1574.012x64.dll` loaded by any process appears.

**No DLL payload execution.** The COR_PROFILER configuration persists in the registry for any future .NET process startup, but within this test's narrow window no .NET application launched under the affected user hive.

**No Sysmon Event 1 for the inner PowerShell fully expanded.** The Sysmon include-mode filter captured the outer PowerShell spawning a child PowerShell, but did not capture individual `New-Item` cmdlet invocations as separate processes (these are in-process).

**Writes target HKU\.DEFAULT, not HKCU.** The test writes to the `.DEFAULT` hive (the profile loaded for processes running as `NT AUTHORITY\SYSTEM` with no interactive session), which is where SYSTEM-context processes inherit environment variables. This means any .NET process running as SYSTEM would be affected — a persistence mechanism rather than a user-scope privilege escalation.

## Assessment

This dataset provides complete telemetry for the COR_PROFILER persistence technique at the registry configuration phase. All four registry writes are captured with their exact values and the full CLSID, making this a precise and complete dataset for the technique's staging behavior. The profiler DLL path pointing to an ART atomics directory is highly suspicious and detectable. Because the configuration persists in the user environment registry hive, the persistence mechanism survives beyond this test execution — the registry artifacts remain until cleaned up.

## Detection Opportunities Present in This Data

- **Sysmon Event 13**: `HKU\.DEFAULT\Environment\COR_ENABLE_PROFILING` set to `1` — enabling CLR profiling for any user/system scope is an unusual configuration outside of developer environments.
- **Sysmon Event 13**: `HKU\.DEFAULT\Environment\COR_PROFILER` set to a non-Microsoft CLSID — profiler CLSID set in user/system environment is a high-confidence indicator.
- **Sysmon Event 13**: `HKU\.DEFAULT\Software\Classes\CLSID\{...}\InprocServer32` pointing to a DLL in `C:\AtomicRedTeam\` — CLSID registration pointing to a non-standard path is suspicious.
- **PowerShell Event 4104**: Script block creating CLSID registry keys and setting `COR_ENABLE_PROFILING`/`COR_PROFILER` — full attack script captured and reconstructable.
- **Sysmon Event 1**: `powershell.exe` spawning child `powershell.exe` with inline registry-modification script — PowerShell→PowerShell with `New-Item` targeting the CLSID hive.
- **Correlation**: `COR_ENABLE_PROFILING`, `COR_PROFILER`, and a CLSID `InprocServer32` all written in the same short window by the same process — the co-occurrence of these three keys is a strong composite indicator of COR_PROFILER abuse.
