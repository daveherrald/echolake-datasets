# T1574.001-1: DLL — DLL Search Order Hijacking - amsi.dll

## Technique Context

T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking) abuses the order in which Windows searches for DLLs when loading an executable. An adversary places a malicious DLL in a directory that appears earlier in the search path than the legitimate DLL location. When a trusted process loads the DLL by name, the malicious copy is loaded instead, executing attacker code in the context of the trusted process.

This test places a renamed copy of `amsi.dll` into `%APPDATA%` and then executes a renamed copy of `powershell.exe` (as `updater.exe`) from the same directory. The expectation is that when `updater.exe` searches for `amsi.dll`, it will find the attacker-controlled copy in its own directory before reaching `System32`.

## What This Dataset Contains

The dataset captures 90 events across Sysmon (42), Security (12), and PowerShell (36) logs collected over approximately 5 seconds on ACME-WS02 (Windows 11 Enterprise, domain-joined).

**The attack execution chain is clearly visible:**

Sysmon Event 1 (Process Create) shows the full command sequence:
- `cmd.exe /c copy %windir%\System32\windowspowershell\v1.0\powershell.exe %APPDATA%\updater.exe & ...`
- `C:\Windows\system32\config\systemprofile\AppData\Roaming\updater.exe -Command exit`

Sysmon Event 11 (File Created) records the artifacts being written to disk:
- `C:\Windows\System32\config\systemprofile\AppData\Roaming\updater.exe` — renamed powershell.exe
- `C:\Windows\System32\config\systemprofile\AppData\Roaming\amsi.dll` — the DLL placed in the hijack path

Sysmon Event 7 (Image Loaded) captures `updater.exe` loading `C:\Windows\System32\amsi.dll`, confirming that despite the attacker placing amsi.dll in AppData, the system loaded the legitimate copy from System32 — Windows Defender's enforcement prevented the hijack from succeeding as intended.

Sysmon Event 10 (Process Access) shows `updater.exe` accessing `MsMpEng.exe`, which is Defender responding to the suspicious process.

Security Event 4688 records process creation for `whoami.exe`, `cmd.exe`, and `updater.exe` with full command lines. Exit codes are all `0x0`, indicating the test framework ran to completion.

PowerShell Event 4103 logs `Set-ExecutionPolicy -Scope Process -Force` — the ART test framework execution policy bypass, present in every test.

## What This Dataset Does Not Contain (and Why)

**The DLL hijack payload did not execute.** Windows Defender's real-time protection (version 4.18.26010.5) detected and blocked the attack. The system loaded `amsi.dll` from `System32` rather than from `AppData`, as confirmed by the Event 7 `ImageLoaded` path. No malicious DLL code ran.

**No Sysmon Event 7 showing amsi.dll loaded from AppData.** This is the definitive signal that the hijack failed — if it had succeeded, you would see `ImageLoaded: C:\Windows\System32\config\systemprofile\AppData\Roaming\amsi.dll`.

**No network connections.** A successful DLL hijack payload would typically establish C2 connectivity; none is present here.

**No privilege escalation artifacts.** The test ran as `NT AUTHORITY\SYSTEM` already; escalation was not the observable goal here.

**Most process creation events are absent from Sysmon.** The sysmon-modular configuration uses include-mode filtering for Event 1, capturing only processes that match known-suspicious patterns. `cmd.exe` and `updater.exe` were captured because the command line matched filter rules; routine processes were not.

## Assessment

This dataset provides a clean example of DLL search order hijacking attempt telemetry under active endpoint protection. The attack artifacts are present — file drops, renamed executable, execution — but the hijack itself was blocked. This is realistic: most modern defenders will see attempt telemetry rather than success telemetry for this technique. The dataset is useful for training detections against the staging behavior rather than the DLL load itself.

## Detection Opportunities Present in This Data

- **Sysmon Event 11**: Executable (`updater.exe`) and DLL (`amsi.dll`) written to `%APPDATA%` by `cmd.exe` within the same short window.
- **Sysmon Event 1**: `powershell.exe` renamed and executed from a non-standard user-writable path; `cmd.exe` with `copy` followed immediately by execution of the copied binary.
- **Sysmon Event 7**: `updater.exe` (a renamed `powershell.exe`) loading Windows system DLLs — the `Image` path being non-system is suspicious regardless of whether the hijack succeeded.
- **Security Event 4688**: Process creation of `updater.exe` from `AppData\Roaming` — execution from user-profile paths is a strong behavioral indicator.
- **Sysmon Event 10**: `updater.exe` accessing `MsMpEng.exe` (Defender process access) — often indicates Defender responding to a threat.
- **PowerShell Event 4103**: `Set-ExecutionPolicy -Scope Process -Force` — consistent with scripted attack test framework initialization.
