# ctid-log_clearing: Clear Windows Event Logs

**MITRE ATT&CK:** [T1070.001](https://attack.mitre.org/techniques/T1070/001) Clear Windows Event Logs
**Tactics:** defense-evasion

The CTID log_clearing emulator clears Windows event logs with wevtutil. The lab run uses the Security-log-only path with --no-safe to avoid the upstream restore-instructions dialog blocking unattended execution; the VM snapshot rollback restores the lab state.

## Telemetry
- **sysmon**: 157 events (EID: 1, 3, 5, 7, 10, 11, 12, 13, 17)
- **security**: 27 events (EID: 1102, 4624, 4672, 4688, 4699, 4720, 4722, 4724, 4726, 4728, 4729, 4732, 4733, 4738, 4798, 4799)
- **powershell**: 266 events (EID: 4100, 4103, 4104, 4105, 4106, 40961, 40962, 53504)
- **system**: 1 events (EID: 7040)
- **wmi**: 3 events (EID: 5857, 5860)

## Capture
- Host `EMU-WS01`, window `2026-06-29T15:21:20Z` .. `2026-06-29T15:22:17Z` (UTC).
- Tool `log_clearing.exe --security --no-safe` launched via transient Task Scheduler action (parent `svchost.exe`).
- `32` orchestration event(s) filtered from the dataset; raw capture scaffolding leaks: `0`.
- `_ingest_time` collapsed to `_event_time`.
