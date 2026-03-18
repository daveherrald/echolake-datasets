# T1490-9: Inhibit System Recovery

**MITRE ATT&CK:** [T1490](https://attack.mitre.org/techniques/T1490)
**Technique:** Inhibit System Recovery
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1490 -TestNumbers 9` — Disable System Restore Through Registry

## Telemetry (83 events)
- **Sysmon**: 30 events
- **Security**: 18 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
