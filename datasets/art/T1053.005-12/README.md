# T1053.005-12: Scheduled Task

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005)
**Technique:** Scheduled Task
**Tactic(s):** execution, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1053.005 -TestNumbers 12` — Scheduled Task Persistence via Eventviewer.msc

## Telemetry (91 events)
- **Sysmon**: 36 events
- **Security**: 17 events
- **Powershell**: 34 events
- **Taskscheduler**: 4 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
