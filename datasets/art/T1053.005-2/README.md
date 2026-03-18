# T1053.005-2: Scheduled Task

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005)
**Technique:** Scheduled Task
**Tactic(s):** execution, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1053.005 -TestNumbers 2` — Scheduled task Local

## Telemetry (79 events)
- **Sysmon**: 32 events
- **Security**: 12 events
- **Powershell**: 34 events
- **Taskscheduler**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
