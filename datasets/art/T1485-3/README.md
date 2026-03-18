# T1485-3: Data Destruction

**MITRE ATT&CK:** [T1485](https://attack.mitre.org/techniques/T1485)
**Technique:** Data Destruction
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1485 -TestNumbers 3` — Overwrite deleted data on C drive

## Telemetry (123 events)
- **Sysmon**: 33 events
- **Security**: 30 events
- **Powershell**: 58 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
