# T1490-2: Inhibit System Recovery

**MITRE ATT&CK:** [T1490](https://attack.mitre.org/techniques/T1490)
**Technique:** Inhibit System Recovery
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1490 -TestNumbers 2` — Windows - Delete Volume Shadow Copies via WMI

## Telemetry (77 events)
- **Sysmon**: 30 events
- **Security**: 13 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
