# T1485-5: Data Destruction

**MITRE ATT&CK:** [T1485](https://attack.mitre.org/techniques/T1485)
**Technique:** Data Destruction
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1485 -TestNumbers 5` — ESXi - Delete VM Snapshots

## Telemetry (69 events)
- **Sysmon**: 23 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
