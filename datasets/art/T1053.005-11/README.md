# T1053.005-11: Scheduled Task

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005)
**Technique:** Scheduled Task
**Tactic(s):** execution, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1053.005 -TestNumbers 11` — Scheduled Task Persistence via CompMgmt.msc

## Telemetry (82 events)
- **Sysmon**: 35 events
- **Security**: 15 events
- **Powershell**: 30 events
- **Taskscheduler**: 2 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
