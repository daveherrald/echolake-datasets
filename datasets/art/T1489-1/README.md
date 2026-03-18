# T1489-1: Service Stop

**MITRE ATT&CK:** [T1489](https://attack.mitre.org/techniques/T1489)
**Technique:** Service Stop
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1489 -TestNumbers 1` — Windows - Stop service using Service Controller

## Telemetry (76 events)
- **Sysmon**: 27 events
- **Security**: 15 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
