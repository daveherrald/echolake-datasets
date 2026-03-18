# T1574.001-2: DLL — Phantom DLL Hijacking - WinAppXRT.dll

## Technique Context

T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking) includes a variant known as phantom DLL hijacking, where the target DLL does not actually exist on the system. When a legitimate application attempts to load a non-existent DLL by name, Windows searches for it across the DLL search path. An adversary who places a DLL with the expected name in an early search path location will have their code loaded by the legitimate process.

This test demonstrates phantom DLL hijacking using `WinAppXRT.dll` — a DLL that Windows applications may attempt to load but which does not ship with the OS. The test copies `amsi.dll` to `%APPDATA%`, renames it to `WinAppXRT.dll`, and places it in `C:\Windows\System32\`. It also sets the registry value `HKU\.DEFAULT\Environment\APPX_PROCESS` to signal the environment modification.

## What This Dataset Contains

The dataset captures 86 events across Sysmon (40), Security (12), and PowerShell (34) logs collected over approximately 6 seconds on ACME-WS02.

**The attack staging is fully recorded:**

Sysmon Event 1 shows the copy and rename chain:
- `cmd.exe /c copy %windir%\System32\amsi.dll %APPDATA%\amsi.dll & ren %APPDATA%\amsi.dll WinAppXRT.dll ...`
- A follow-on `reg add "HKEY_CURRENT_USER\Environment" /v APPX_PROCESS /t REG_EXPAND_SZ /d "1" /f`

Sysmon Event 11 (File Created) captures:
- `C:\Windows\System32\config\systemprofile\AppData\Roaming\amsi.dll` — intermediate copy
- `C:\Windows\System32\WinAppXRT.dll` — the phantom DLL placed in System32

Sysmon Event 13 (Registry Value Set) captures:
- `TargetObject: HKU\.DEFAULT\Environment\APPX_PROCESS` with `Details: 1`

Sysmon Event 10 (Process Access) shows `powershell.exe` accessing `whoami.exe` and `cmd.exe`, consistent with test framework process spawning.

Security Event 4688 records `whoami.exe`, `cmd.exe`, and `reg.exe` with full command lines. The `reg.exe` exit code `0x0` confirms the registry write succeeded.

## What This Dataset Does Not Contain (and Why)

**The phantom DLL was not loaded by any process.** Placing `WinAppXRT.dll` in System32 is a staging action; a vulnerable application would need to launch and attempt to load the DLL to complete the technique. No such application execution occurred in this test window, and Sysmon Event 7 shows no load of `WinAppXRT.dll`.

**No Sysmon Event 7 for the phantom DLL.** If a susceptible process had loaded the DLL, an Event 7 with `ImageLoaded: C:\Windows\System32\WinAppXRT.dll` would appear. Its absence indicates either no vulnerable process ran or Defender prevented any load.

**No DLL execution artifacts.** No network connections, no injected thread activity, no child processes spawned from the hypothetical DLL payload.

**Sysmon Event 1 does not capture all process creations.** The include-mode filter means only processes matching suspicious patterns appear; `cmd.exe` and `reg.exe` were caught because their command lines matched, but other routine processes during the test window are absent.

## Assessment

This dataset captures the staging phase of a phantom DLL hijack: the malicious DLL is dropped and an environment variable is set, but no victim process loaded it. This is realistic for a detection dataset — the preparation artifacts are more reliably detectable than the DLL load itself, which only occurs when a specific application starts. The file drop into System32 and the registry modification together form a meaningful detection opportunity.

## Detection Opportunities Present in This Data

- **Sysmon Event 11**: DLL written to `C:\Windows\System32\` by `cmd.exe` — system32 write access from a user-mode process is highly anomalous.
- **Sysmon Event 11**: `amsi.dll` copy written to `AppData\Roaming` — copying security-sensitive DLLs to user-writable paths is suspicious staging behavior.
- **Sysmon Event 13**: Registry key `HKU\.DEFAULT\Environment\APPX_PROCESS` set — modification of user environment registry values under the DEFAULT profile warrants investigation.
- **Sysmon Event 1**: `cmd.exe` command line containing `copy ... amsi.dll` and `ren ... WinAppXRT.dll` — renaming system DLLs is an explicit indicator.
- **Security Event 4688**: `reg.exe` with `HKEY_CURRENT_USER\Environment` modification — environment variable manipulation at process scope is a persistence staging pattern.
- **PowerShell Event 4103**: `Set-ExecutionPolicy -Scope Process -Force` — standard ART test framework boilerplate, indicating scripted execution context.
