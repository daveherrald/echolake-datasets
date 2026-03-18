# T1490-6: Inhibit System Recovery

**MITRE ATT&CK:** [T1490](https://attack.mitre.org/techniques/T1490)
**Technique:** Inhibit System Recovery
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1490 -TestNumbers 6` — Windows - Delete Backup Files

## Telemetry (74 events)
- **Sysmon**: 27 events
- **Security**: 11 events
- **Powershell**: 34 events
- **Application**: 1 events
- **Taskscheduler**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
