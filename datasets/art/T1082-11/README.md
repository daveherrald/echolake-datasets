# T1082-11: System Information Discovery

**MITRE ATT&CK:** [T1082](https://attack.mitre.org/techniques/T1082)
**Technique:** System Information Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1082 -TestNumbers 11` — Environment variables discovery on windows

## Telemetry (79 events)
- **Sysmon**: 26 events
- **Security**: 12 events
- **Powershell**: 34 events
- **System**: 1 events
- **Taskscheduler**: 6 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
