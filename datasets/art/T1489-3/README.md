# T1489-3: Service Stop

**MITRE ATT&CK:** [T1489](https://attack.mitre.org/techniques/T1489)
**Technique:** Service Stop
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1489 -TestNumbers 3` — Windows - Stop service by killing process

## Telemetry (72 events)
- **Sysmon**: 24 events
- **Security**: 13 events
- **Powershell**: 34 events
- **System**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
