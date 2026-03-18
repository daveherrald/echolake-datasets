# T1053.005-5: Scheduled Task

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005)
**Technique:** Scheduled Task
**Tactic(s):** execution, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1053.005 -TestNumbers 5` — Task Scheduler via VBA (Invoke-MalDoc)

## Telemetry (130 events)
- **Sysmon**: 29 events
- **Security**: 10 events
- **Powershell**: 91 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
