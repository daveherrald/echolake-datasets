# T1105-7: Ingress Tool Transfer

**MITRE ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105)
**Technique:** Ingress Tool Transfer
**Tactic(s):** command-and-control
**ART Test:** `Invoke-AtomicTest T1105 -TestNumbers 7` — certutil download (urlcache)

## Telemetry (67 events)
- **Sysmon**: 15 events
- **Security**: 11 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
