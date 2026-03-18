# T1105-9: Ingress Tool Transfer

**MITRE ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105)
**Technique:** Ingress Tool Transfer
**Tactic(s):** command-and-control
**ART Test:** `Invoke-AtomicTest T1105 -TestNumbers 9` — Windows - BITSAdmin BITS Download

## Telemetry (108 events)
- **Sysmon**: 48 events
- **Security**: 20 events
- **Powershell**: 40 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
