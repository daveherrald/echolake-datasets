# T1562.001-11: Disable or Modify Tools — Unload Sysmon Filter Driver

## Technique Context

T1562.001 (Disable or Modify Tools) covers adversary actions that disable or tamper with security software to blind defenders. This test unloads the SysmonDrv kernel-mode filter driver using `fltmc.exe`, the Windows Filter Manager Control Program. Successfully unloading SysmonDrv terminates Sysmon's ability to monitor process creation, network connections, file operations, and registry changes — immediately eliminating a primary source of endpoint telemetry. This is a well-known anti-forensics technique documented in multiple real-world intrusion campaigns.

The critical detection challenge: once SysmonDrv is unloaded, Sysmon can no longer generate its own events about subsequent activity. This dataset captures the last Sysmon events before the driver goes dark.

## What This Dataset Contains

The dataset captures 75 events across Sysmon, Security, PowerShell, and System logs collected during a 6-second window on 2026-03-14 at 01:21 UTC.

The fltmc unload command is visible in Security EID 4688:

```
"cmd.exe" /c fltmc.exe unload SysmonDrv
```

And further decomposed:

```
fltmc.exe  unload SysmonDrv
```

Key observations from the data:

- Security EID 4688 records `cmd.exe` with the full `fltmc.exe unload SysmonDrv` command line, spawned by `powershell.exe` as SYSTEM.
- Security EID 4688 records `fltmc.exe` itself as a separate process creation event.
- **Sysmon EID 1** fires for `cmd.exe` (RuleName: `technique_id=T1059.003,technique_name=Windows Command Shell`) and for `fltmc.exe` (RuleName: `technique_id=T1518.001,technique_name=Security Software Discovery`). The T1518.001 annotation reflects the sysmon-modular rule that flags fltmc.exe invocations as potential security software discovery/tampering.
- **Sysmon EID 255** (Error Report) is the terminal event before the driver unloads: `ID: DriverCommunication`, `Description: Failed to retrieve events - Last error: The I/O operation has been aborted because of either a thread exit or an application request.` This is Sysmon's own error event documenting that its driver communication channel was severed.
- **System EID 1** records the filter driver unload: `File System Filter 'SysmonDrv' (Version 0.0, 2024-07-22T08:29:55.000000000Z) unloaded successfully.` This is the Windows Filter Manager's own log of the operation.
- Sysmon EID 7 fires for the standard PowerShell DLL load chain before the driver unload.
- Sysmon EID 10 (ProcessAccess) and EID 17 (PipeCreate) represent ART test framework artifacts from output capture and PowerShell named pipe setup.
- PowerShell EID 4104 and 4103 contain only ART boilerplate scriptblocks.

The combination of Sysmon EID 255 and System EID 1 creates a correlated record: Sysmon self-reports loss of driver communication, and the Windows Filter Manager independently confirms SysmonDrv was unloaded.

## What This Dataset Does Not Contain (and Why)

**No Sysmon events after the driver unload.** Once SysmonDrv is unloaded, Sysmon cannot generate further events. Any activity following the unload is invisible to Sysmon. This is the fundamental threat: the dataset ends abruptly from a Sysmon perspective.

**No Security EID 4657 (registry key written).** Object access auditing is disabled. The fltmc operation does not modify the registry directly, so no registry audit events are generated.

**No re-load of SysmonDrv in this dataset.** ART cleanup would reload the driver, but that occurs after the dataset time window.

**No Defender block.** Windows Defender does not block fltmc.exe from unloading filter drivers when running as SYSTEM. The unload succeeds as evidenced by System EID 1.

## Assessment

This is an exceptionally high-value dataset because it captures a complete Sysmon self-termination event. The triple-corroboration — Security EID 4688 (process creation with command line), Sysmon EID 255 (driver communication failure), and System EID 1 (filter driver unloaded) — provides multiple independent detection paths for the same action. The Sysmon EID 255 in particular is a unique telemetry artifact that can only occur when Sysmon's own driver communication is interrupted; defenders who monitor for this event have a reliable anti-tampering indicator. The dataset demonstrates why Sysmon alone is insufficient: once its driver is unloaded, all subsequent activity is invisible until the service is restored.

## Detection Opportunities Present in This Data

- **Sysmon EID 255**: `DriverCommunication` error with `I/O operation has been aborted` — direct indicator of Sysmon driver being unloaded or tampered with. High fidelity, very low false-positive rate.
- **System EID 1**: Filter driver `SysmonDrv` unloaded successfully — Windows Filter Manager's own audit trail of the operation.
- **Sysmon EID 1**: `fltmc.exe` process creation (RuleName: `technique_id=T1518.001`) with `unload SysmonDrv` in the command line — available in Sysmon because the event fires before the driver is torn down.
- **Security EID 4688**: `cmd.exe` with `fltmc.exe unload SysmonDrv` command line and `fltmc.exe` process creation, spawned from PowerShell as SYSTEM.
- **Temporal gap detection**: Sudden cessation of Sysmon events from a host that was previously generating normal telemetry is itself a detection signal — the absence of events is the alert.
- **Correlation**: `fltmc.exe unload` targeting any filter driver name associated with security software (SysmonDrv, WdFilter, etc.) from a non-administrative context.
