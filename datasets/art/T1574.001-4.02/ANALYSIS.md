# T1574.001-4: DLL Search Order Hijacking — DLL Side-Loading using the Notepad++ GUP.exe binary

## Technique Context

T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking) includes **DLL side-loading**, where an adversary exploits a legitimate, signed executable that loads DLLs by relative path rather than absolute path. Because the application searches its own directory first, an attacker who can write a malicious DLL to the same directory as the trusted binary will have their code loaded under that binary's identity.

`GUP.exe` is the update utility bundled with Notepad++. It is a signed, trusted binary that loads several DLLs from its working directory by relative path, making it a documented side-loading candidate. This test places a pre-built malicious DLL (from the ART atomics repository at `C:\AtomicRedTeam\atomics\T1574.002\bin\`) alongside `GUP.exe` and executes the binary, expecting the DLL to be side-loaded and a calculator process to be spawned as a payload indicator.

## What This Dataset Contains

The dataset captures 120 events across two log sources: PowerShell (107 events: 104 EID 4104, 3 EID 4103) and Security (13 events: 7 EID 4689, 5 EID 4688, 1 EID 4703). All events were collected on ACME-WS06 (Windows 11 Enterprise, domain-joined, Defender disabled).

**The attack execution is visible through Security EID 4688.** PowerShell spawned cmd.exe to launch `GUP.exe` directly from the ART atomics binary directory:

```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\T1574.002\bin\GUP.exe"
```

This confirms GUP.exe was executed from a non-standard path — not from its expected Notepad++ installation directory, but from the ART atomics staging area. The cleanup phase is captured as a separate EID 4688:

```
"cmd.exe" /c taskkill /F /IM calculator.exe >nul 2>&1
```

This spawned `taskkill.exe` with the command line:

```
taskkill /F /IM calculator.exe
```

The `taskkill` targeting `calculator.exe` is the standard ART cleanup for side-loading payloads that launch a calculator as a benign payload indicator — and its presence as a cleanup action implies that `calculator.exe` was running (i.e., the side-load executed successfully). All five EID 4688 process creation events exited at `0x0`.

Security EID 4703 records the PowerShell host process (PID 0x440c) receiving an expanded privilege set including `SeLoadDriverPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege`, and others — consistent with SYSTEM-context execution.

## What This Dataset Does Not Contain

**No Sysmon events are present.** Without Sysmon EID 1 (Process Create with full image hash and parent chain), EID 7 (Image Loaded — which would show which DLLs GUP.exe loaded and from where), or EID 11 (File Created — which would capture the DLL drop), you cannot directly observe the side-loading mechanism from this data alone. The presence of `taskkill /F /IM calculator.exe` strongly implies success, but the DLL load itself is not recorded.

**No file write events.** The placement of the malicious DLL alongside `GUP.exe` occurs before this dataset's collection window.

**No network activity.** The ART payload used here (calc spawner) generates no network connections.

## Assessment

The defended variant recorded 26 Sysmon, 10 Security, and 35 PowerShell events. In that run, Defender detected and blocked the side-load, and `calculator.exe` was never spawned — the `taskkill` cleanup process would have found nothing to kill. In this undefended run, the cleanup explicitly targets `calculator.exe`, which implies the payload DLL ran and launched the calculator successfully. The attack succeeded end-to-end.

The undefended dataset is notably smaller (120 events vs. 71 in defended — actually larger here due to PS verbosity) but crucially shows `GUP.exe` executing from the ART binary staging path and the subsequent `taskkill` cleanup confirming payload success. The Security channel provides clear visibility into the execution chain without Sysmon, though it lacks the hash-level and DLL-load-level detail that Sysmon would provide.

## Detection Opportunities Present in This Data

**EID 4688 — GUP.exe launching from a non-standard path.** `C:\AtomicRedTeam\atomics\T1574.002\bin\GUP.exe` is immediately anomalous. Legitimate Notepad++ updates run GUP.exe from `C:\Program Files\Notepad++\updater\`. Any execution of `GUP.exe` from a user-writable path or a tools directory warrants investigation.

**EID 4688 — taskkill targeting calculator.exe immediately after GUP.exe execution.** The `taskkill /F /IM calculator.exe` command appearing in direct temporal proximity to `GUP.exe` execution is a recognizable artifact of ART side-loading tests. In a real attack, the payload would not be a calculator, but the cleanup pattern — terminating a process spawned by the side-loaded DLL — would follow the same structure.

**EID 4688 — cmd.exe spawned by PowerShell running as SYSTEM to execute a third-party binary.** PowerShell (SYSTEM context) → cmd.exe → GUP.exe is an unusual execution chain for a legitimate update utility. GUP.exe is typically invoked by Notepad++ itself, not by a PowerShell/cmd wrapper.

**Process lineage anomaly.** Correlating the creator process chain (PowerShell → cmd.exe → GUP.exe) against the expected parent for GUP.exe (Notepad++) would flag this execution immediately.
