# T1057-5: Process Discovery

**MITRE ATT&CK:** [T1057](https://attack.mitre.org/techniques/T1057)
**Technique:** Process Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1057 -TestNumbers 5` — Process Discovery - wmic process

## Telemetry (77 events)
- **Sysmon**: 30 events
- **Security**: 13 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
