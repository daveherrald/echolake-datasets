# T1218.011-14: Rundll32 — Running DLL with .init Extension and Function

## Technique Context

T1218.011 covers the abuse of `rundll32.exe` to proxy the execution of arbitrary code while hiding under a trusted, Microsoft-signed binary. The standard defensive assumption is that `rundll32.exe` loads files ending in `.dll`. This test challenges that assumption: it loads a file with a `.init` extension and calls an export named `krnl`.

The command line is:

```
rundll32.exe C:\AtomicRedTeam\atomics\T1218.011\bin\_WT.init,krnl
```

Detection rules that filter for `rundll32.exe` loading `.dll` files miss this entirely. The technique demonstrates that `rundll32.exe` does not enforce file extensions — it loads whatever binary the path points to. The `.init` extension is deliberately chosen to look like an initialization configuration file rather than executable code. The export name `krnl` is also chosen to look unremarkable at first glance.

This variant is particularly relevant for organizations using EDR rules that match `rundll32` combined with unusual extensions, and for defenders building behavioral models around what `rundll32.exe` "normally" loads.

## What This Dataset Contains

This dataset provides a complete, successful execution chain with both Security and Sysmon telemetry fully populated.

**Security EID 4688** captures four process creation events in sequence:

1. `whoami.exe` (PID 0x4664) spawned by `powershell.exe` (PID 0x3efc) — ART pre-execution check.
2. `cmd.exe` (PID 0x4108) spawned by `powershell.exe` with command line: `"cmd.exe" /c rundll32.exe C:\AtomicRedTeam\atomics\T1218.011\bin\_WT.init,krnl`
3. `rundll32.exe` (PID 0x4570) spawned by `cmd.exe` with command line: `rundll32.exe  C:\AtomicRedTeam\atomics\T1218.011\bin\_WT.init,krnl`
4. `C:\Windows\SysWOW64\rundll32.exe` (PID 0x4798) spawned by the System32 `rundll32.exe` — the 64-bit loader spawned a 32-bit rundll32 to match the architecture of the `.init` payload, which indicates the DLL is 32-bit.

The 64→32-bit rundll32 chain (System32 → SysWOW64) is itself a behavioral indicator. Legitimate applications rarely need to invoke the WOW64 rundll32 this way.

**Sysmon EID 1** confirms the `cmd.exe` and `rundll32.exe` process creations with full command line visibility, hashes, and integrity levels. All processes run as `NT AUTHORITY\SYSTEM` with `IntegrityLevel: System`. The `cmd.exe` hash is `SHA1=94BDAEB55589339BAED714F681B4690109EBF7FE`.

**Sysmon EID 7** (27 events) records DLL loads into both rundll32 instances and powershell. The specific DLLs loaded into `rundll32.exe` are not fully captured in the sample set, but the high count of image loads is consistent with `_WT.init` executing and pulling in dependencies.

**Sysmon EID 10** (4 events) shows process access events from `powershell.exe` to `whoami.exe` and `cmd.exe` with `GrantedAccess: 0x1FFFFF` — the ART test framework pattern.

Total event counts: 2 Application (EID 15), 113 PowerShell, 6 Security (EID 4688), 41 Sysmon.

The undefended dataset contains 41 Sysmon events compared to 21 in the defended variant. The additional events reflect the full execution of `_WT.init,krnl` with Defender absent.

## What This Dataset Does Not Contain

The Sysmon samples do not include EID 7 records specifically showing `_WT.init` being mapped into `rundll32.exe`'s memory. While 27 image-load events were captured, the sample set does not surface the specific `_WT.init` load event. A complete Sysmon EID 7 for the payload file itself would conclusively demonstrate the DLL being loaded under a non-`.dll` extension.

There are no Sysmon EID 11 (file creation) or EID 13 (registry) events showing any persistence or side-effects from `krnl` executing. The payload's behavior after execution is not represented. If `krnl` performed additional actions (file writes, network connections, registry modifications), those artifacts are absent from the captured data.

The PowerShell channel (113 events) contains only test framework boilerplate — `Set-StrictMode`, `Set-ExecutionPolicy Bypass`, and framework scriptblocks. The technique itself was executed via `cmd.exe`, not through PowerShell cmdlets.

## Assessment

This is an excellent undefended dataset for the file-extension-bypass variant of T1218.011. The full `powershell.exe` → `cmd.exe` → `rundll32.exe` → `SysWOW64\rundll32.exe` chain is cleanly documented in Security EID 4688 events with command lines preserved. The 64→32 rundll32 pivot is an unusually specific behavioral signal. The dataset is particularly valuable for validating detection logic that targets non-`.dll` extensions in `rundll32` invocations, since the command line is directly observable in the Security channel.

Compared to the defended variant (21 Sysmon, 16 Security, 30 PowerShell), this dataset adds 20 additional Sysmon events reflecting unimpeded execution and has 6 Security events versus 16 — suggesting that in the defended run, more process creation events (including possible cleanup or relaunch attempts) were logged.

## Detection Opportunities Present in This Data

The following behavioral observables are directly present in the event records:

- **Security EID 4688** contains `rundll32.exe` loading a file path ending in `.init` — any `rundll32.exe` invocation pointing to a non-`.dll` file is a strong behavioral anomaly.
- **Security EID 4688** shows `System32\rundll32.exe` spawning `SysWOW64\rundll32.exe` with an identical command line. This 64→32-bit proxy pattern is unusual for legitimate software and worth flagging as a behavioral indicator.
- **Sysmon EID 1** records the full command line with hash values for `cmd.exe` and `rundll32.exe`, enabling hash-based correlation with other datasets where the same binary is observed.
- **Security EID 4688** shows the parent-child chain `powershell.exe` → `cmd.exe` → `rundll32.exe` with the non-standard DLL path, providing three separate anchoring points for a detection rule.
- The export name `krnl` in the rundll32 command line is atypical; real DLLs using `krnl` as a public export name outside of kernel shims are rare. The combination of a non-standard extension and a suspicious export name is a high-confidence indicator.
