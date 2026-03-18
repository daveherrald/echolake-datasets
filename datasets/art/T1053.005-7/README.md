# T1053.005-7: Scheduled Task

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005)
**Technique:** Scheduled Task
**Tactic(s):** execution, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1053.005 -TestNumbers 7` — Scheduled Task Executing Base64 Encoded Commands From Registry

## Telemetry (93 events)
- **Sysmon**: 43 events
- **Security**: 14 events
- **Powershell**: 34 events
- **Taskscheduler**: 2 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
