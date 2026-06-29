# ctid-named_pipes: Named Pipes

**MITRE ATT&CK:** [T1559](https://attack.mitre.org/techniques/T1559) Inter-Process Communication
**Tactics:** execution

The CTID named_pipes emulator (executor/server/client) creates a Cobalt-Strike-pattern named pipe (\\.\pipe\MSSE-a09-server), the client connects, data is exchanged, then it closes. Distinctive pipe name mimics CS Artifact Kit.

## Telemetry
- **sysmon**: 79 events (EID: 1, 5, 7, 10, 11, 12, 13, 15, 17, 18, 25)
- **security**: 19 events (EID: 4688, 4699)
- **powershell**: 76 events (EID: 4103, 4104, 4105, 4106, 40961, 40962, 53504)
- **wmi**: 5 events (EID: 5857, 5858)

## Capture
- Host `EMU-WS01`, window `2026-06-28T16:40:13Z` .. `2026-06-28T16:41:13Z` (UTC).
- Tool `namedpipes_executor.exe --pipe 1 --server C:\Windows\Temp\tools\named_pipes\build\namedpipes_server.exe --client C:\Windows\Temp\tools\named_pipes\build\namedpipes_client.exe` launched via transient Task Scheduler action (parent `svchost.exe`).
- `28` orchestration event(s) filtered from the dataset; raw capture scaffolding leaks: `0`.
- `_ingest_time` collapsed to `_event_time`.
