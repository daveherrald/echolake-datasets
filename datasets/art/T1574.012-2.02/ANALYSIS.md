# T1574.012-2: COR_PROFILER — System Scope COR_PROFILER

## Technique Context

T1574.012 (Hijack Execution Flow: COR_PROFILER) abuses the .NET Common Language Runtime (CLR) profiling API to inject attacker-controlled code into every managed (.NET) process that starts on the system. The CLR checks three environment variables at startup: `COR_ENABLE_PROFILING` (enables profiling), `COR_PROFILER` (a CLSID identifying the profiler), and `COR_PROFILER_PATH` (the full path to the profiler DLL). When these are set, the CLR loads the nominated DLL before executing any managed code.

This test (variant 2) sets all three variables in the **system-scope environment** — under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` — using PowerShell's `New-ItemProperty`. System-scope variables apply to all processes system-wide, making this a persistent, machine-wide DLL injection primitive. Every .NET application launched on the host (including system components, update agents, and user applications) will load the profiler DLL until the variables are removed.

## What This Dataset Contains

The dataset captures 127 events across two log sources: PowerShell (114 events: 108 EID 4104, 6 EID 4103) and Security (13 events: 8 EID 4689, 4 EID 4688, 1 EID 4703). All events were collected on ACME-WS06 (Windows 11 Enterprise, domain-joined, Defender disabled).

**The system environment variable setup is fully captured in Security EID 4688.** PowerShell spawned a child PowerShell process with the complete attack command line:

```
"powershell.exe" & {Write-Host "Creating system environment variables" -ForegroundColor Cyan
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  -Name "COR_ENABLE_PROFILING" -PropertyType String -Value "1" -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  -Name "COR_PROFILER" -PropertyType String -Value "{09108e71-974c-4010-89cb-acf471ae9e2c}" -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  -Name "COR_PROFILER_PATH" -PropertyType String -Value "C:\AtomicRedTeam\atomics\T1574.012\bin\T1574.012x64.dll" -Force | Out-Null}
```

This establishes:
- Profiling enabled system-wide (`COR_ENABLE_PROFILING = 1`)
- Profiler CLSID `{09108e71-974c-4010-89cb-acf471ae9e2c}`
- Profiler DLL path: `C:\AtomicRedTeam\atomics\T1574.012\bin\T1574.012x64.dll`

The cleanup phase is also captured — a separate PowerShell child process (EID 4688) was created with:

```
"powershell.exe" & {Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  -Name "COR_ENABLE_PROFILING" -Force -ErrorAction Ignore | Out-Null
Remove-ItemProperty ... -Name "COR_PROFILER" ...
Remove-ItemProperty ... -Name "COR_PROFILER_PATH" ...}
```

All four EID 4688 process creation events exited at `0x0`, confirming both setup and cleanup completed successfully.

Security EID 4703 records the parent PowerShell host (PID 0x45a8) receiving elevated privileges including `SeLoadDriverPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege`, and `SeSecurityPrivilege` — consistent with SYSTEM-context execution.

## What This Dataset Does Not Contain

**No Sysmon events are present.** Without Sysmon EID 13 (Registry Value Set), you do not have a dedicated event recording the three `COR_*` value writes under `HKLM\...\Session Manager\Environment`. The writes are visible only through the PowerShell command line in EID 4688. Without Sysmon EID 7 (Image Loaded), you cannot confirm whether any .NET process loaded `T1574.012x64.dll` during the window the variables were active.

**No .NET process execution events showing the profiler loading.** The test sets the variables and immediately removes them without launching a .NET target application in between. Whether any background .NET process picked up the variables during the brief window is unknown from this data.

**No Sysmon EID 12 (Registry Key Create) for the individual `HKLM\...\Environment` values.**

## Assessment

The defended variant recorded 29 Sysmon, 10 Security, and 37 PowerShell events. In that run, Sysmon EID 13 events captured the three `COR_*` registry writes directly. The undefended run is smaller in Sysmon coverage (zero events) but the Security channel here provides the full `New-ItemProperty` command lines with the exact CLSID and DLL path — arguably the most actionable indicators. The Security EID 4688 for the setup PowerShell process captures the complete attack intent in a single record.

The undefended run confirms that all three environment variables were written to the system-scope registry path and subsequently cleaned up — operations that in the defended run triggered Defender telemetry but were allowed to complete. The attack window is narrow (the variables were set and then immediately removed), but the DLL path and CLSID are both clearly visible in the command lines.

## Detection Opportunities Present in This Data

**EID 4688 — PowerShell writing `COR_ENABLE_PROFILING`, `COR_PROFILER`, and `COR_PROFILER_PATH` to `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`.** These three variable names together under the system environment path are a textbook COR_PROFILER attack. Legitimate applications that require .NET profiling (such as APM tools or diagnostic instruments) configure this at deployment time via proper installers, not via ad-hoc `New-ItemProperty` commands from a scripted context.

**EID 4688 — CLSID `{09108e71-974c-4010-89cb-acf471ae9e2c}` in a PowerShell command line.** This CLSID is the ART test's synthetic profiler identifier. In a real attack, the CLSID would be different, but any unknown or recently registered CLSID appearing in a `COR_PROFILER` assignment should be investigated against COM registry entries.

**EID 4688 — COR_PROFILER_PATH pointing to a non-standard directory.** The path `C:\AtomicRedTeam\atomics\T1574.012\bin\T1574.012x64.dll` is obviously a test artifact. In production, any `COR_PROFILER_PATH` pointing to a user-writable directory, a temp path, or a non-vendor installation directory is suspicious.

**EID 4688 — Immediate cleanup of `COR_*` registry values from a scripted context.** Rapid creation and removal of system-scope CLR profiler environment variables is a behavioral pattern consistent with testing or with an attacker attempting to limit their exposure window while still ensuring profiler code executes.
