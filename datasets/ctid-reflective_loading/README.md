# ctid-reflective_loading: Reflective Code Loading

**MITRE ATT&CK:** [T1620](https://attack.mitre.org/techniques/T1620) Reflective Code Loading, [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery, [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery
**Tactics:** defense-evasion, discovery

The CTID reflective_loading emulator reflectively executes shellcode in the current process. The shellcode launches PowerShell discovery commands including whoami, qwinsta, tasklist, Win32_product WMI inventory, and netstat. In the current Windows 11 lab build, the reliable captured signals are the reflective_loading process start, image load, and termination; the payload discovery commands did not produce a clean non-harness signal.

## Telemetry
- **sysmon**: 148 events (EID: 1, 3, 5, 7, 10, 11, 12, 13, 17, 22)
- **security**: 18 events (EID: 4624, 4672, 4688, 4698, 4699, 4798)
- **powershell**: 253 events (EID: 4100, 4103, 4104, 4105, 4106, 40961, 40962, 53504)
- **application**: 1 events (EID: 1023)
- **wmi**: 8 events (EID: 5857)

## Capture
- Host `EMU-WS01`, window `2026-06-29T15:53:19Z` .. `2026-06-29T15:54:46Z` (UTC).
- Tool `reflective_loading.exe --dinvoke` launched via transient Task Scheduler action (parent `svchost.exe`).
- `64` orchestration event(s) filtered from the dataset; raw capture scaffolding leaks: `0`.
- `_ingest_time` collapsed to `_event_time`.
