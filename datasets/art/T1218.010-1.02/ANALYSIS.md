# T1218.010-1: Regsvr32 — Local COM Scriptlet Execution

## Technique Context

T1218.010 covers adversary abuse of `regsvr32.exe`, the Windows COM DLL registration utility. While `regsvr32.exe` is designed to register and unregister COM DLLs, it also accepts `.sct` (Windows Script Component) scriptlet files via the `/i:` parameter when combined with `scrobj.dll`. Scriptlet files are XML documents containing JScript or VBScript code that executes when `regsvr32.exe` processes the file. This technique — often called "Squiblydoo" — allows execution of arbitrary script code through a signed Microsoft binary.

In this local variant, the scriptlet is pre-staged on disk at `C:\AtomicRedTeam\atomics\T1218.010\src\RegSvr32.sct` and referenced by absolute path. The command pattern `regsvr32.exe /s /u /i:"C:\...\RegSvr32.sct" scrobj.dll` is the canonical form: `/s` (silent), `/u` (unregister), `/i:` (install path), with `scrobj.dll` as the COM object to activate. The `-u` flag causes the scriptlet's `<unregistration>` block to execute rather than the `<registration>` block — a subtle evasion that some rules miss.

In the defended variant of this test, `regsvr32.exe` exits with status `0x5` (ACCESS_DENIED) — Defender blocks it. This undefended dataset captures what happens when the defense is absent.

The dataset was collected on ACME-WS06 (Windows 11 Enterprise, domain-joined to acme.local) with Windows Defender disabled.

## What This Dataset Contains

The dataset contains 134 total events: 107 PowerShell, 5 Security, and 22 Sysmon.

**Security EID 4688 records the attack chain:**

1. `"cmd.exe" /c C:\Windows\system32\regsvr32.exe /s /u /i:"C:\AtomicRedTeam\atomics\T1218.010\src\RegSvr32.sct" scrobj.dll` — cmd.exe with the regsvr32 invocation
2. `C:\Windows\system32\regsvr32.exe /s /u /i:"C:\AtomicRedTeam\atomics\T1218.010\src\RegSvr32.sct" scrobj.dll` — regsvr32.exe executing the scriptlet
3. `"C:\Windows\system32\whoami.exe"` — ATH framework success verification (two executions)
4. `"cmd.exe" /c` — cleanup command

The regsvr32.exe command line is unambiguous: the `/i:` parameter points directly to a `.sct` file and `scrobj.dll` follows as the target module. The `/s /u` flags confirm silent unregistration mode.

**Sysmon EID 1** captures 5 process creation events:
- `powershell.exe` → `whoami.exe` (`RuleName: technique_id=T1033`, two events)
- `cmd.exe` (the regsvr32 wrapper, `RuleName: technique_id=T1059.003`)
- `regsvr32.exe` (`CommandLine: C:\Windows\system32\regsvr32.exe /s /u /i:"C:\AtomicRedTeam\atomics\T1218.010\src\RegSvr32.sct" scrobj.dll`, `ParentImage: C:\Windows\System32\cmd.exe`, `RuleName: technique_id=T1218.010`)
- `cmd.exe` (cleanup)

The Sysmon rule `technique_id=T1218.010,technique_name=Regsvr32` fires directly on the regsvr32 process creation — a specific, targeted rule in the sysmon-modular configuration.

**Sysmon EID 7 (Image Load)** records 11 events for .NET runtime DLLs in the test framework PowerShell. Note: `scrobj.dll` loading within `regsvr32.exe` is not captured in the sample set, but the process creation event confirms it was invoked.

**Sysmon EID 10 (Process Access)** records 4 full-access events from PowerShell to `whoami.exe` and `cmd.exe`.

**Sysmon EID 17 (Pipe Created)** records 1 event for the PowerShell host pipe.

**Sysmon EID 3 (Network Connection)** records 1 event showing `MsMpEng.exe` (Windows Defender's engine process, which runs even when Defender is "disabled" in real-time protection mode) connecting outbound to `48.211.72.139` port 443 from `192.168.4.16`. This is ambient Defender telemetry, not directly related to the regsvr32 execution.

## What This Dataset Does Not Contain

In the defended variant, `regsvr32.exe` exited with `0x5` (ACCESS_DENIED), meaning no scriptlet content executed and no child processes were spawned beyond the regsvr32 binary itself. In this undefended dataset, the technique succeeded — the `whoami.exe` executions confirm the scriptlet's payload ran. However, the scriptlet's specific actions beyond spawning `whoami.exe` are not captured.

No file creation events show the `.sct` file being read or any output files being written by the scriptlet payload.

No DNS queries (Sysmon EID 22) appear, consistent with a local-only scriptlet that doesn't require network communication. The network connection visible in EID 3 is from `MsMpEng.exe`, not from `regsvr32.exe`.

The scriptlet content itself is not logged anywhere — `regsvr32.exe` reads and executes the `.sct` file directly without triggering PowerShell script block logging.

## Assessment

This dataset provides clean, complete telemetry for a successful undefended Regsvr32 local scriptlet execution. The critical difference from the defended variant is execution success: the regsvr32 process and its `whoami.exe` child both complete with exit code `0x0` here, versus the `0x5` ACCESS_DENIED in the defended run. The Sysmon `technique_id=T1218.010` rule fires directly on the process creation event, making this one of the more directly detectable techniques in the T1218 family.

Compared to the defended variant (29 Sysmon, 12 Security, 34 PowerShell), this undefended run produced fewer Sysmon (22 vs. 29) and Security (5 vs. 12) events, consistent with the absence of Defender-generated audit activity.

## Detection Opportunities Present in This Data

**Security EID 4688 (regsvr32.exe):** The command line `C:\Windows\system32\regsvr32.exe /s /u /i:"C:\AtomicRedTeam\atomics\T1218.010\src\RegSvr32.sct" scrobj.dll` is a direct indicator. The pattern `/i:` with a `.sct` file extension combined with `scrobj.dll` is the canonical "Squiblydoo" signature. Any `regsvr32.exe` command line containing `/i:` and `scrobj.dll` should be investigated.

**Sysmon EID 1 (regsvr32.exe, RuleName=T1218.010):** The sysmon-modular rule `technique_id=T1218.010,technique_name=Regsvr32` fires directly. This is a targeted rule that doesn't require behavioral analysis — process creation alone triggers it.

**Process Chain:** `powershell.exe → cmd.exe → regsvr32.exe → whoami.exe` (where whoami is spawned by the scriptlet payload). `regsvr32.exe` spawning child processes is anomalous and should alert regardless of the specific child process.

**Sysmon EID 3 (MsMpEng.exe network connection):** Even with Defender disabled, `MsMpEng.exe` makes outbound connections. This is ambient telemetry but confirms the Defender binary is running and may be performing cloud lookups triggered by the regsvr32 activity — even in a "disabled" state.
