# T1555.003-7: Credentials from Web Browsers — Simulating access to Windows Edge Login Data

## Technique Context

T1555.003 (Credentials from Web Browsers) includes targeting Microsoft Edge, which stores credentials in an SQLite database (`Login Data`) under `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\`. Because Edge is Chromium-based, the file format and encryption method (DPAPI) are the same as Chrome. Attackers copy this profile directory to decrypt credentials offline or on another system. This test simulates that exfiltration step.

## What This Dataset Contains

The dataset spans five seconds on 2026-03-14 on ACME-WS02 (Windows 11 Enterprise, domain acme.local). The core action was a PowerShell `Copy-Item` copying the Edge profile:

```
Copy-Item "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default" -Destination "C:\AtomicRedTeam\atomics\..\ExternalPayloads\Edge" -Force -Recurse
```

This appears in EID 4104 (script block logging) twice — both the `& { ... }` invocation form and the bare block. EID 4103 records the standard ART test framework `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`.

Sysmon events include:
- **EID 1** (Process Create): `whoami.exe` (tagged T1033) and a `powershell.exe` child (tagged T1059.001)
- **EID 7** (ImageLoad): DLLs loaded into PowerShell — `mscoree.dll`, .NET Framework v4 assemblies — tagged T1055/T1059.001/T1574.002
- **EID 10** (ProcessAccess): PowerShell cross-process access tagged T1055.001, characteristic of the ART test framework's .NET hosting model
- **EID 11** (FileCreate): PowerShell transcript files written to the SYSTEM profile
- **EID 17** (PipeCreate): Named PSHost pipes for both PowerShell instances

Security events: EID 4688/4689 (process create/exit) and EID 4703 (token right adjusted) for SYSTEM.

## What This Dataset Does Not Contain (and Why)

**No file access events for the Edge Login Data file.** Object access auditing is disabled, so no EID 4663 records reflect the actual credential database read. Windows has no native visibility into which files were copied.

**No DPAPI decryption events.** The test only copies the files; actual decryption (which would involve DPAPI calls and potentially EID 4688 for `dpapi.dll` use) was not performed on-system.

**No Sysmon EID 1 for the Copy-Item subprocess.** The copy operation runs inside the PowerShell process — no child process is spawned. Only the test framework-invoked `whoami.exe` and the test's spawned `powershell.exe` were captured by include-mode Sysmon rules.

**No network activity.** Only local staging; no exfiltration simulation.

## Assessment

This dataset closely mirrors T1555.003-6 (Firefox) in structure. The distinguishing telemetry is the EID 4104 script block showing the Edge-specific path (`Microsoft\Edge\User Data\Default`). On a system where Edge is actively used, this path would contain a populated `Login Data` SQLite file. The overall event volume is lower than the Firefox test (26 Sysmon events vs. 45), which likely reflects fewer DLL loads for the Edge test's PowerShell invocation.

## Detection Opportunities Present in This Data

- **EID 4104**: Script block explicitly references `$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default` — a known browser credential path. Any PowerShell copying this path to a staging location is high-confidence suspicious.
- **EID 4688**: Process creation for `powershell.exe` under SYSTEM on a domain workstation warrants investigation, particularly when command-line logging shows no interactive session context.
- **EID 1 (Sysmon)**: `whoami.exe` spawned from PowerShell is consistent with post-access enumeration typical of credential theft tooling.
- **Pattern matching**: The combination of Copy-Item targeting browser profile directories (`\Edge\`, `\Chrome\`, `\Firefox\`) with a non-standard destination is a reliable detection pattern that applies across T1555.003 variants.
