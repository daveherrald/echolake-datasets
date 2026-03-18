# T1049-7: System Network Connections Discovery

**MITRE ATT&CK:** [T1049](https://attack.mitre.org/techniques/T1049)
**Technique:** System Network Connections Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1049 -TestNumbers 7` — System Discovery using SharpView

## Telemetry (81 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
