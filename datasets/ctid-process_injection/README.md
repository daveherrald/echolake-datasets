# ctid-process_injection: Process Injection

**MITRE ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055) Process Injection, [T1055.002](https://attack.mitre.org/techniques/T1055/002) Portable Executable Injection
**Tactics:** defense-evasion, privilege-escalation

The CTID process_injection emulator creates a suspended svchost.exe, allocates and writes shellcode into it, and runs it via CreateRemoteThread; the injected shellcode performs in-memory discovery (whoami, netstat, qwinsta, tasklist), then cleans up.

## Telemetry
- **sysmon**: 63 events (EID: 1, 5, 7, 8, 10, 11, 13, 15, 17, 25)
- **security**: 54 events (EID: 4624, 4672, 4688, 4702)
- **system**: 7 events (EID: 113, 10016, 10121, 10148)
- **application**: 3 events (EID: 1, 15)
- **wmi**: 3 events (EID: 5857, 5858, 5860)

## Capture
- Host `EMU-WS01`, window `2026-06-28T14:39:22Z` .. `2026-06-28T14:40:02Z` (UTC).
- Tool `process_injection.exe -r 20 -l C:\Windows\Temp\tools\pi_log.txt` launched via transient Task Scheduler action (parent `svchost.exe`).
- `22` orchestration event(s) filtered from the dataset; raw capture scaffolding leaks: `0`.
- `_ingest_time` collapsed to `_event_time`.
