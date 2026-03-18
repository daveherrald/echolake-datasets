# T1053.002-1: At

**MITRE ATT&CK:** [T1053.002](https://attack.mitre.org/techniques/T1053/002)
**Technique:** At
**Tactic(s):** execution, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1053.002 -TestNumbers 1` — At.exe Scheduled task

## Telemetry (64 events)
- **Sysmon**: 18 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
