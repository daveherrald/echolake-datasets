# T1489-1: Service Stop — Windows stop service using Service Controller

## Technique Context

T1489 (Service Stop) describes adversary operations that terminate or disable services to impair defenses, disrupt operations, or enable subsequent attack stages. Ransomware operators systematically stop backup services (Volume Shadow Copy, Windows Backup), database services (SQL Server, Exchange, MySQL), and endpoint security services immediately before encryption — stopping these services prevents file locking that would interfere with encryption and disables recovery mechanisms. `sc.exe stop <service>` is the most direct mechanism, invoking the Windows Service Control Manager API to request a graceful service stop.

Test T1489-1 uses `sc.exe stop spooler` to stop the Windows Print Spooler service as a demonstration target. The Print Spooler is chosen because it can be stopped and restarted without causing lasting harm — it is not a production backup or database service. The ART cleanup step restarts the service with `sc.exe start spooler`. Both phases are captured in this dataset.

## What This Dataset Contains

This dataset captures a complete, successful service stop and restart cycle with full telemetry across all channels.

**Security EID 4688** documents the complete process chain. PowerShell (running as `NT AUTHORITY\SYSTEM`) spawns `cmd.exe` with:

```
"cmd.exe" /c sc.exe stop spooler
```

`cmd.exe` spawns `sc.exe stop spooler`. Both process creation events are captured with full command lines. `sc.exe` exits with `0x0` (success), confirming the service stop request was accepted by the Service Control Manager.

The cleanup phase is also fully captured: `cmd.exe /c sc.exe start spooler` followed by `sc.exe start spooler`. Security EID 4688 records `spoolsv.exe` being launched by `services.exe` (`C:\Windows\system32\services.exe`) as the Service Control Manager restarts it — this is the service resuming operation after the ART cleanup.

Security EID 4624 and 4672 are present, reflecting a logon and special privilege assignment — these correspond to the SYSTEM context the test framework operates under and are background infrastructure events.

Seven total Security EID 4688 events cover: test framework `whoami.exe` (×2), attack-phase `cmd.exe`, attack-phase `sc.exe stop spooler`, cleanup `cmd.exe`, cleanup `sc.exe start spooler`, and the `spoolsv.exe` restart launched by `services.exe`.

**Sysmon EID 1** captures seven ProcessCreate events. Key events:
- `cmd.exe` with `"cmd.exe" /c sc.exe stop spooler`, tagged `technique_id=T1059.003,technique_name=Windows Command Shell`
- `sc.exe stop spooler` with parent `cmd.exe`, tagged `technique_id=T1543.003,technique_name=Windows Service`
- `sc.exe start spooler` (cleanup) with parent `cmd.exe`
- `spoolsv.exe` launched by `services.exe` — the service restoring after cleanup

The Sysmon tagging directly identifies this as Windows Service manipulation (`T1543.003`), demonstrating the ruleset correctly fires on `sc.exe` usage patterns.

**Sysmon EID 17** captures two named pipe events:
- `\PSHost.*.DefaultAppDomain.powershell` — the PowerShell host pipe (standard)
- `\Winsock2\CatalogChangeListener-41d0-0` — a pipe created by `spoolsv.exe` when it restarts, reflecting the Print Spooler's Winsock catalog initialization

The `spoolsv.exe` pipe event is a secondary confirmation that the Print Spooler service actually came back up — it creates this Winsock catalog listener pipe during initialization.

**Sysmon EID 10** shows four process access events from PowerShell accessing `whoami.exe` and `cmd.exe`.

The PowerShell channel (107 events) is test framework boilerplate only, as expected — the technique is driven by cmd.exe and sc.exe, not PowerShell scripting.

**Compared to the defended variant** (27 Sysmon / 15 Security / 34 PowerShell): The undefended run has fewer events (23 Sysmon / 9 Security). Since Defender does not block `sc.exe stop` against the Print Spooler, the technique succeeds in both variants. The defended run's higher event counts are attributable to Defender's process inspection overhead. The service stop and restart succeed identically in both runs.

## What This Dataset Does Not Contain

The Windows System channel is not bundled in this dataset. System EID 7036 ("The Print Spooler service entered the stopped state") and EID 7036 (resumed state) are the most commonly cited service-stop detection events in many security stacks — their absence here is a meaningful gap. The dataset captures the `sc.exe` invocation evidence but not the Service Control Manager's own recording of the service state transition. Adding the System channel to this collection would significantly improve the dataset's completeness for teams that rely on System EID 7036 for service-stop detection.

Security EID 4697 (a service was installed) and Security EID 4657 (registry object change) are also absent — object access auditing is disabled, so the service registry key modifications are not logged.

## Assessment

This is a high-quality, compact dataset for the `sc.exe stop` service termination pattern. All three critical events are present: the `sc.exe stop spooler` invocation with full command line, the `spoolsv.exe` process termination (confirming the service actually stopped), and the subsequent `sc.exe start spooler` with `spoolsv.exe` restart (confirming cleanup). The Sysmon `T1543.003` rule tagging is correctly applied. The `spoolsv.exe` Winsock pipe event in Sysmon EID 17 is a nice secondary confirmation of service restoration.

The primary practical limitation is the absence of System EID 7036. Many production detection rules anchor on EID 7036 for service-stop detection, so datasets built for that detection class will need the System channel added.

For detections based on process creation (Security 4688 / Sysmon EID 1), this dataset is complete and clean.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `sc.exe stop <service_name>` spawned by `cmd.exe` from a `powershell.exe` parent. The service name in the command line identifies the target. For production detection, the most valuable service names to watch for are `vss`, `sqlwriter`, `wdnissvc`, `windefend`, `wuauserv`, and backup service names — `spooler` here is a stand-in.
- **Sysmon EID 1**: `sc.exe` with `stop` argument tagged `technique_id=T1543.003` — the sysmon-modular ruleset correctly identifies sc.exe service manipulation.
- **Security EID 4689**: `spoolsv.exe` (or any targeted service binary) exiting with `0x0` shortly after an `sc.exe stop` invocation is a correlated sequence that confirms the service actually stopped, not just that the command was run.
- **Security EID 4688**: `services.exe` spawning `spoolsv.exe` (or any previously-stopped service binary) shortly after a stop event — the restart confirms the full stop/start lifecycle, which is a characteristic of testing and cleanup behavior vs. a real attack that would leave the service stopped.
- **Sysmon EID 17**: Named pipe creation by a service binary immediately following a restart is a secondary confirmation of service state transitions not covered by System EID 7036.
