# T1574.001-3: DLL — Phantom DLL Hijacking - ualapi.dll

## Technique Context

T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking) includes phantom DLL hijacking, where an adversary plants a DLL with a name that a legitimate Windows component will attempt to load but that does not normally exist on the system. `ualapi.dll` is one such target: the Windows Print Spooler service (`spoolsv.exe`) attempts to load it at startup but Windows does not ship this DLL in `System32`. Placing a malicious `ualapi.dll` in `C:\Windows\System32\` causes it to be loaded by `spoolsv.exe` when the service starts.

This test copies `amsi.dll` to `%APPDATA%`, renames it to `ualapi.dll`, copies the result to `System32`, and then restarts the Print Spooler service (`sc config Spooler start=auto`) to trigger the load.

## What This Dataset Contains

The dataset captures 66 events across Sysmon (20), Security (12), and PowerShell (34) logs collected over approximately 4 seconds on ACME-WS02.

**The staging chain is recorded:**

Sysmon Event 1 shows the preparation commands:
- `cmd.exe /c copy %windir%\System32\amsi.dll %APPDATA%\amsi.dll & ren %APPDATA%\amsi.dll ualapi.dll ...`
- `sc config Spooler start=auto` — configuring the Spooler service to ensure it runs on restart

Sysmon Event 11 (File Created) captures:
- `C:\Windows\System32\config\systemprofile\AppData\Roaming\amsi.dll` — intermediate staging copy
- `C:\Windows\System32\ualapi.dll` — the phantom DLL placed in System32

Sysmon Event 13 (Registry Value Set) shows:
- `TargetObject: HKLM\System\CurrentControlSet\Services\Spooler\Start` — confirming the service start type was modified (the `sc config` command committed to registry by `services.exe`)

Security Event 4688 records `whoami.exe`, `cmd.exe`, and `sc.exe` with full command lines. All exit at `0x0`.

## What This Dataset Does Not Contain (and Why)

**The ualapi.dll was not loaded by spoolsv.exe.** Triggering the DLL load requires a full Spooler service restart, which did not occur within the narrow 4-second capture window of this test. No Event 7 showing `ualapi.dll` loaded by `spoolsv.exe` is present.

**No Spooler process activity.** The Print Spooler service did not start or restart during data capture, so no `spoolsv.exe` events appear.

**No DLL payload execution.** No network connections, no spawned children, no injected code evidence — the attack did not reach the execution phase.

**No Sysmon Event 1 for sc.exe spawning services.** The Sysmon include filter captured `sc.exe` because `sc` is in the suspicious process list, but the Services Control Manager's own internal service operations do not produce Event 1 under the include-mode filter.

**Fewer Sysmon events overall (20 vs. 40+ in other tests)** because no target process loaded the DLL and the Spooler did not restart.

## Assessment

This dataset captures the staging phase of a ualapi.dll phantom hijack targeting the Print Spooler. The DLL drop into System32 and service configuration change are recorded, but the exploit payload never fired. The dataset is most useful for detection against the staging behavior — DLL drops into system directories and service configuration changes — which are reliable precursor signals. The Spooler phantom DLL path is well-documented in threat intelligence and `ualapi.dll` writes to System32 should never occur in a healthy environment.

## Detection Opportunities Present in This Data

- **Sysmon Event 11**: `ualapi.dll` written to `C:\Windows\System32\` — this file should never exist there legitimately; any instance is a high-confidence indicator.
- **Sysmon Event 11**: `amsi.dll` written to `AppData\Roaming` — intermediate staging file, anomalous use of a security DLL name.
- **Sysmon Event 13**: `HKLM\System\CurrentControlSet\Services\Spooler\Start` modified by `services.exe` following `sc config` — service configuration changes targeting well-known services warrant review.
- **Sysmon Event 1**: `sc.exe config Spooler start=auto` — modifying Spooler startup configuration is an unusual administrative action on a workstation.
- **Sysmon Event 1**: `cmd.exe` command line with `copy ... amsi.dll` followed by `ren ... ualapi.dll` — DLL staging by renaming a security module is explicit attack behavior.
- **Security Event 4688**: `sc.exe` with Spooler configuration argument — process creation telemetry correlates the `sc` invocation with the registry change.
