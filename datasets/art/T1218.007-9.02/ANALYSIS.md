# T1218.007-9: Msiexec — Execute the DllRegisterServer Function of a DLL

## Technique Context

T1218.007-9 exploits a lesser-known capability of `msiexec.exe`: the `/y` command-line switch, which calls the `DllRegisterServer` export of a specified DLL. This is distinct from the MSI package installation variants (tests 1, 4, 6, 11) — no MSI file is involved. The attacker simply points `msiexec.exe` at a malicious DLL, and `msiexec.exe` loads and calls `DllRegisterServer()`. Since `msiexec.exe` is a trusted signed binary, this bypasses application controls that would block the DLL from being loaded directly.

The `/y` switch is documented in Microsoft's `msiexec.exe` help text: it is intended for registering DLL-based COM servers during software installation. Attackers repurpose it to proxy arbitrary DLL code execution through a trusted binary.

Detection engineering challenges: `msiexec.exe` loading a DLL via `/y` generates no Windows Installer application log entries (unlike actual MSI installations), and the DLL execution happens in-process — only child processes spawned by the DLL are visible in process creation logs.

The dataset was collected on ACME-WS06 (Windows 11 Enterprise, domain-joined to acme.local) with Windows Defender disabled.

## What This Dataset Contains

The dataset contains 141 total events: 105 PowerShell, 6 Security, and 30 Sysmon. Notably, there are no Application log events — confirming the `/y` switch does not trigger the Windows Installer transaction infrastructure.

**Security EID 4688 captures the complete process chain:**

1. `"cmd.exe" /c c:\windows\system32\msiexec.exe /y "C:\AtomicRedTeam\atomics\T1218.007\bin\MSIRunner.dll"` — cmd.exe with the /y flag
2. `c:\windows\system32\msiexec.exe /y "C:\AtomicRedTeam\atomics\T1218.007\bin\MSIRunner.dll"` — msiexec.exe loading and calling DllRegisterServer
3. `powershell.exe -nop -Command Write-Host DllRegisterServer export executed me; exit` — the DLL's DllRegisterServer function spawning PowerShell to prove execution
4. `"C:\Windows\system32\whoami.exe"` — ATH framework success verification (two executions)

**Sysmon EID 1** captures the chain with parent-child relationships:
- `powershell.exe` (test framework) → `cmd.exe` (`RuleName: technique_id=T1059.003`)
- `cmd.exe` → `msiexec.exe` (`CommandLine: c:\windows\system32\msiexec.exe /y "C:\AtomicRedTeam\atomics\T1218.007\bin\MSIRunner.dll"`, `RuleName: technique_id=T1218`)
- `msiexec.exe` → `powershell.exe` (`-nop -Command Write-Host DllRegisterServer export executed me; exit`)
- Two `whoami.exe` executions

**Sysmon EID 10 (Process Access)** records 4 full-access events from PowerShell to `whoami.exe` and `cmd.exe`, tagged `technique_id=T1055.001`.

**Sysmon EID 7 (Image Load)** produces 17 events for .NET runtime and Windows Defender DLLs in the test framework PowerShell process.

**Sysmon EID 17 (Pipe Created)** records 2 pipe creation events for PowerShell host communication.

**Sysmon EID 11 (File Created)** records 1 event: `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive`.

**PowerShell EID 4104** captures test framework boilerplate and `Write-Host "DONE"` (test completion marker). EID 4103 module logging events also appear, documenting cmdlet invocations.

## What This Dataset Does Not Contain

There are no Application log events (EID 1040, 1033, etc.), confirming that `msiexec.exe /y` bypasses the Windows Installer transaction logging that appears in MSI package installations. This is a meaningful distinguishing characteristic: absence of Application log entries can differentiate `/y` DLL loading from actual MSI package installation.

No Sysmon EID 11 events show `MSIRunner.dll` being created or written — the DLL was pre-staged in `C:\AtomicRedTeam\atomics\T1218.007\bin\` before the test window.

No network events appear, consistent with local-only DLL execution.

## Assessment

This dataset provides clear, complete telemetry for a successful `/y`-flag DLL execution via `msiexec.exe` with Defender disabled. The spawned PowerShell process (`-nop -Command Write-Host DllRegisterServer export executed me; exit`) conclusively confirms that `DllRegisterServer` in the test DLL was called and successfully executed arbitrary code. All processes exit with status `0x0`.

Compared to the defended variant (48 Sysmon, 15 Security, 40 PowerShell), this undefended run produced fewer events across all channels. The defended run's higher Sysmon count reflects Defender scanning the DLL load and the spawned PowerShell process more aggressively.

The absence of Application log entries here versus their presence in T1218.007-1, -4, -6, and -11 is itself a detection opportunity: a `msiexec.exe /y` execution can be identified specifically because it produces the msiexec process chain without the corresponding Windows Installer application log activity.

## Detection Opportunities Present in This Data

**Security EID 4688:** The command line `c:\windows\system32\msiexec.exe /y "C:\AtomicRedTeam\atomics\T1218.007\bin\MSIRunner.dll"` contains the `/y` switch — which has essentially no legitimate use case in normal enterprise operations. Any `msiexec.exe` invocation with `/y` is worth immediate investigation.

**Sysmon EID 1:** `msiexec.exe` spawning `powershell.exe -nop -Command ...` is captured. `msiexec.exe` spawning PowerShell is anomalous in real installations; it indicates a custom action or (in this case) a DllRegisterServer export that calls `CreateProcess`.

**Absence of Application Log Events:** In a SIEM context, correlating `msiexec.exe` process creation events in Security or Sysmon against the absence of Windows Installer application log entries (EIDs 1033, 1040, 1042, 11707) narrows down `/y`-flag DLL loading versus actual MSI package installation — a more nuanced but actionable behavioral differentiator.

**Sysmon EID 10:** Full-access process access from PowerShell to `cmd.exe` and `whoami.exe` is present, adding to the behavioral chain for investigation.
