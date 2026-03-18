# T1053.005-1: Scheduled Task

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005)
**Technique:** Scheduled Task
**Tactic(s):** execution, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1053.005 -TestNumbers 1` — Scheduled Task Startup Script

## Telemetry (90 events, noise-filtered)
- **Powershell**: 34 events
- **Security**: 16 events
- **Sysmon**: 38 events
- **Taskscheduler**: 2 events

## Pipeline
Events from ACME-WS02 via Cribl Edge.
Infrastructure noise filtered (qemu-ga, Cribl, NSSM, ART framework overhead).
