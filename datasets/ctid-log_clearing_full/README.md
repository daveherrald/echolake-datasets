# ctid-log_clearing_full: Clear Windows Event Logs (Full Default)

**MITRE ATT&CK:** [T1070.001](https://attack.mitre.org/techniques/T1070/001) Clear Windows Event Logs
**Tactics:** defense-evasion

The CTID log_clearing emulator clears Security, System, and Application logs with its upstream no-argument path. The executable also displays restore instructions after clearing the logs; the harness terminates that prompt after the telemetry has been produced because the VM snapshot is the lab restore boundary.

## Telemetry
- **sysmon**: 124 events (EID: 1, 3, 5, 7, 10, 11, 12, 13, 17)
- **security**: 20 events (EID: 1102, 4624, 4672, 4688, 4699)
- **powershell**: 273 events (EID: 4100, 4103, 4104, 4105, 4106, 40961, 40962, 53504)
- **system**: 2 events (EID: 104)
- **wmi**: 1 events (EID: 5857)

## Capture
- Host `EMU-WS01`, window `2026-06-29T16:43:32Z` .. `2026-06-29T16:44:44Z` (UTC).
- Tool `log_clearing.exe ` launched via transient Task Scheduler action (parent `svchost.exe`).
- `55` orchestration event(s) filtered from the dataset; raw capture scaffolding leaks: `0`.
- `_ingest_time` collapsed to `_event_time`.
