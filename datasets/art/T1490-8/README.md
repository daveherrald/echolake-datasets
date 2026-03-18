# T1490-8: Inhibit System Recovery

**MITRE ATT&CK:** [T1490](https://attack.mitre.org/techniques/T1490)
**Technique:** Inhibit System Recovery
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1490 -TestNumbers 8` — Windows - Disable the SR scheduled task

## Telemetry (86 events)
- **Sysmon**: 38 events
- **Security**: 12 events
- **Powershell**: 35 events
- **Taskscheduler**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
