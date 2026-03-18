# T1562.001-36: Disable or Modify Tools — Disable Windows Defender with PwSh Disable-WindowsOptionalFeature

## Technique Context

MITRE ATT&CK T1562.001 (Disable or Modify Tools) includes removing Windows Defender entirely as an OS optional feature. The `Disable-WindowsOptionalFeature` PowerShell cmdlet wraps the Windows DISM (Deployment Image Servicing and Management) API and can be used to remove Windows features, including the Defender GUI, Defender runtime, and Application Guard. Adversaries who operate with SYSTEM-level privilege on an unmanaged or enterprise endpoint may attempt this approach to permanently remove Defender rather than simply disabling its configuration settings.

## What This Dataset Contains

The dataset captures 10 seconds of telemetry from ACME-WS02 and is among the richest in this series — it includes system, task scheduler, security, Sysmon, and PowerShell events. DISM was successfully invoked and spawned multiple `DismHost.exe` processes, indicating that the feature management pipeline engaged.

**Security 4688 — Process creation for the attack and DISM chain:**
```
"powershell.exe" & {Disable-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-Gui" -NoRestart -ErrorAction Ignore
Disable-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-Features" -NoRestart -ErrorAction Ignore
Disable-WindowsOptionalFeature -Online -FeatureName "Windows-Defender" -NoRestart -ErrorAction Ignore
Disable-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -ErrorAction Ignore}
```
Additional 4688 events for: `DismHost.exe` (four invocations), `TrustedInstaller.exe`, `TiWorker.exe`, `sdbinst.exe`.

**PowerShell 4100 — Three error events, one per unrecognized feature name:**
```
Error Message = Feature name Windows-Defender-Gui is unknown.
Error Message = Feature name Windows-Defender-Features is unknown.
Error Message = Feature name Windows-Defender is unknown.
```
These errors indicate the feature names used in this ART test do not match the feature names present on Windows 11 Enterprise Evaluation. `Windows-Defender-ApplicationGuard` did not produce an error (it may have had a different failure mode or was silently skipped via `-ErrorAction Ignore`).

**Sysmon EID 1 — Three process creates:** `whoami.exe`, the child `powershell.exe`, and `sdbinst.exe` (application compatibility database installer, spawned by the DISM pipeline).

**System EID 7040 — Service startup type changed:**
```
The start type of the Windows Modules Installer service was changed from demand start to auto start.
The start type of the Windows Modules Installer service was changed from auto start to demand start.
```
The Windows Modules Installer service (TrustedInstaller) was temporarily set to auto-start to support the DISM feature modification attempt, then reset to demand-start.

**TaskScheduler events (EID 100, 102, 129, 200, 201):** The `SdbinstMergeDbTask` task executed `sdbinst.exe` as part of application compatibility processing triggered by the DISM operation.

**Security 4624/4627/4672 — Logon and privilege events:** A Logon Type 5 (service) logon for SYSTEM with `SeDebugPrivilege` and `SeLoadDriverPrivilege` was triggered by the DISM/TrustedInstaller pipeline.

## What This Dataset Does Not Contain (and Why)

**Successful feature removal** — Defender was not removed. The feature names in the ART test script do not match the correct Windows 11 feature names (`Windows-Defender-Gui` etc. are incorrect; the actual feature names differ by Windows edition and release). All four DISM attempts encountered unknown feature errors.

**Driver removal or registry cleanup events** — No Sysmon registry or file events related to Defender component removal appear, consistent with the feature names being rejected before any modification was applied.

**Fourth PowerShell 4100 error** — `Windows-Defender-ApplicationGuard` did not produce a 4100 error. With `-ErrorAction Ignore`, this call either succeeded silently or the error was suppressed without logging a 4100 event.

## Assessment

This is a **partially blocked / failed execution** dataset. DISM was invoked and TrustedInstaller activated (the System EID 7040 events confirm this), but the specific feature names used by ART are incorrect for Windows 11 Enterprise Evaluation, causing DISM to report unknown feature errors. The dataset is valuable because it shows the full chain of OS-level side effects even from a failed attempt: `DismHost.exe` spawned four times, TrustedInstaller ran, `sdbinst.exe` executed via a scheduled task, and a SYSTEM service logon occurred. These secondary signals are observable even when the primary goal fails. Defenders who see this combination of processes without any recognized software installation activity should investigate.

## Detection Opportunities Present in This Data

- **`Disable-WindowsOptionalFeature` with Defender feature names** (PowerShell 4104 / Security 4688): The cmdlet call with any `Windows-Defender*` feature name is a high-confidence indicator, regardless of whether the feature name is valid.
- **`DismHost.exe` spawned from `powershell.exe`** (Security 4688): DISM being invoked from a PowerShell session running as SYSTEM is unusual outside of system administration workflows and is worth alerting.
- **`TrustedInstaller.exe` activation** (Security 4688 / System EID 7040): The Windows Modules Installer service changing start type from `demand` to `auto` then back to `demand` within seconds is a signature of a DISM feature modification attempt.
- **`sdbinst.exe` spawned by TaskScheduler during an unexpected feature operation**: `sdbinst.exe` executing via the `SdbinstMergeDbTask` scheduled task as a side effect of a DISM call correlates with the DISM pipeline being engaged.
- **PowerShell 4100 with `DisableWindowsOptionalFeatureCommand`**: Errors from this cmdlet during unusual session contexts confirm attempted Defender feature removal.
