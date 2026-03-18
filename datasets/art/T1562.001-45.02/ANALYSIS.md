# T1562.001-45: Disable or Modify Tools — AMSI Bypass - Override AMSI via COM

## Technique Context

MITRE ATT&CK T1562.001 (Disable or Modify Tools) includes bypassing the Antimalware Scan Interface (AMSI), which allows Windows security products to scan script and buffer content at runtime. This test overrides the AMSI COM server registration by writing a fake `InProcServer32` path under `HKCU\Software\Classes\CLSID\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}` — the CLSID for the AMSI COM object (`amsi.dll`). By redirecting the COM registration to a non-existent DLL (`C:\IDontExist.dll`), the AMSI object fails to instantiate, causing AMSI scanning to silently fail for processes that honor per-user COM registration. This technique targets user-hive COM redirection rather than system-level AMSI patching, making it stealthier than in-memory approaches that patch `AmsiScanBuffer` directly.

Because the test ran as `NT AUTHORITY\SYSTEM`, the write landed under `HKU\.DEFAULT` rather than a named user's `HKCU` hive — functionally equivalent for the SYSTEM account but worth noting for detection purposes.

## What This Dataset Contains

The dataset spans roughly four seconds and captures 39 events across PowerShell (35) and Security (4) channels.

**Security (EID 4688):** Four process creation events document the execution chain. PowerShell (PID 0x45b4) spawns `whoami.exe` twice — the ART test framework pre- and post-execution identity checks. Between those, PowerShell spawns `cmd.exe` with the full attack command:

```
"cmd.exe" /c REG ADD HKCU\Software\Classes\CLSID\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\InProcServer32 /ve /t REG_SZ /d C:\IDontExist.dll /f
```

`cmd.exe` (PID 0x4478) then spawns `reg.exe` (PID 0x4514) executing the same `REG ADD` command directly. All processes run under `S-1-5-18` (SYSTEM) with `TokenElevationTypeDefault (1)` and `MandatoryLabel S-1-16-16384` (System integrity).

**PowerShell (EID 4104):** 35 script block logging events, almost entirely ART test framework boilerplate — batches of four internal PowerShell error-handling closures (`{ Set-StrictMode -Version 1; $_.PSMessageDetails }` etc.) repeated across multiple PowerShell runspace startups. The one substantive block is the cleanup invocation:

```
try {
    Invoke-AtomicTest T1562.001 -TestNumbers 45 -Cleanup -Confirm:$false 2>&1 | Out-Null
} catch {}
```

No `REG ADD` or CLSID-specific content appears in the PowerShell log because the actual technique executes through `cmd.exe` and `reg.exe`, not PowerShell cmdlets.

## What This Dataset Does Not Contain

**No Sysmon events.** This undefended dataset was collected without Sysmon channel data in scope (EID breakdown: security 4688 only). The defended variant captured Sysmon Event ID 13 (RegistryValue Set) confirming the write to `HKU\.DEFAULT\Software\Classes\CLSID\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\InProcServer32` with value `C:\IDontExist.dll`, plus Sysmon Event ID 1 with full process chain. That Sysmon telemetry is absent here.

**No AMSI bypass validation.** The dataset captures the registry write but not any subsequent test of whether AMSI is effectively disabled. No process that loads AMSI and attempts a scan appears.

**No in-memory AMSI patching.** This is a COM registration approach. No memory writes, `VirtualProtect` calls, or `WriteProcessMemory` events are present.

**Fewer events than the defended variant.** The defended run produced 22 Sysmon + 12 Security + 34 PowerShell events (68 total). The undefended run produced 35 PowerShell + 4 Security events (39 total). The difference reflects the absence of Sysmon data in the undefended channel set and the absence of the MpCmdRun.exe telemetry subprocess that appeared in the defended run.

## Assessment

The technique executed successfully. The Security EID 4688 events confirm the full execution chain: PowerShell → cmd.exe → reg.exe, with the CLSID redirection command captured verbatim in the command-line field. Because Defender was disabled in this environment, there was no Defender block, no tamper protection, and no MpCmdRun.exe activity — the write proceeded without interference.

The undefended dataset demonstrates what the technique looks like without any security tooling active: a clean, minimal footprint consisting of two `whoami.exe` checks flanking a `cmd.exe`/`reg.exe` pair. No Sysmon registry telemetry is present to confirm the write was completed; you are relying entirely on the process creation record.

Compared to the defended variant, this dataset has fewer total events and lacks the Sysmon registry confirmation, but the core Security 4688 evidence of the `reg.exe` command line is present and functionally identical.

## Detection Opportunities Present in This Data

- **Security EID 4688:** `reg.exe` command line containing `CLSID\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}` and `InProcServer32` — the specific AMSI COM object CLSID is a reliable indicator. Any write to this CLSID under any user hive warrants investigation.
- **Security EID 4688:** `cmd.exe` spawned by `powershell.exe` with a `REG ADD` command targeting `HKCU\Software\Classes\CLSID` — COM hijacking via command shell is unusual in normal operations.
- **Parent-child chain:** `powershell.exe` → `cmd.exe` → `reg.exe` with a HKCU CLSID target is a recognizable pattern for COM-based security bypass without requiring Sysmon registry monitoring.
