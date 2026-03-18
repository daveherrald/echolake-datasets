# T1490-7: Inhibit System Recovery

**MITRE ATT&CK:** [T1490](https://attack.mitre.org/techniques/T1490)
**Technique:** Inhibit System Recovery
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1490 -TestNumbers 7` — Windows - wbadmin Delete systemstatebackup

## Telemetry (53 events)
- **Sysmon**: 18 events
- **Security**: 12 events
- **Powershell**: 23 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
