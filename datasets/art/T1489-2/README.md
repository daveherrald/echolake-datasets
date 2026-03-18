# T1489-2: Service Stop

**MITRE ATT&CK:** [T1489](https://attack.mitre.org/techniques/T1489)
**Technique:** Service Stop
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1489 -TestNumbers 2` — Windows - Stop service using net.exe

## Telemetry (77 events)
- **Sysmon**: 28 events
- **Security**: 15 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
