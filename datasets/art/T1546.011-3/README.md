# T1546.011-3: Application Shimming

**MITRE ATT&CK:** [T1546.011](https://attack.mitre.org/techniques/T1546/011)
**Technique:** Application Shimming
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.011 -TestNumbers 3` — Registry key creation and/or modification events for SDB

## Telemetry (88 events)
- **Sysmon**: 41 events
- **Security**: 10 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
