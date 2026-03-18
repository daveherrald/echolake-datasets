# T1012-3: Query Registry

**MITRE ATT&CK:** [T1012](https://attack.mitre.org/techniques/T1012)
**Technique:** Query Registry
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1012 -TestNumbers 3` — Enumerate COM Objects in Registry with Powershell

## Telemetry (1543 events)
- **Sysmon**: 62 events
- **Security**: 54 events
- **Powershell**: 1421 events
- **System**: 2 events
- **Application**: 2 events
- **Wmi**: 1 events
- **Taskscheduler**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
