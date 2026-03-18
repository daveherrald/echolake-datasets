# T1124-5: System Time Discovery

**MITRE ATT&CK:** [T1124](https://attack.mitre.org/techniques/T1124)
**Technique:** System Time Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1124 -TestNumbers 5` — System Time with Windows time Command

## Telemetry (60 events)
- **Sysmon**: 16 events
- **Security**: 10 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
