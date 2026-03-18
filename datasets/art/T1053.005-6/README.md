# T1053.005-6: Scheduled Task

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005)
**Technique:** Scheduled Task
**Tactic(s):** execution, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1053.005 -TestNumbers 6` — WMI Invoke-CimMethod Scheduled Task

## Telemetry (112 events)
- **Sysmon**: 50 events
- **Security**: 11 events
- **Powershell**: 49 events
- **Taskscheduler**: 2 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
