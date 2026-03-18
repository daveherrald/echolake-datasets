# T1105-34: Ingress Tool Transfer

**MITRE ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105)
**Technique:** Ingress Tool Transfer
**Tactic(s):** command-and-control
**ART Test:** `Invoke-AtomicTest T1105 -TestNumbers 34` — Windows push file using scp.exe

## Telemetry (100 events)
- **Sysmon**: 44 events
- **Security**: 14 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
