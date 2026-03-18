# T1546-8: Event Triggered Execution

**MITRE ATT&CK:** [T1546](https://attack.mitre.org/techniques/T1546)
**Technique:** Event Triggered Execution
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546 -TestNumbers 8` — Persistence via ErrorHandler.cmd script execution

## Telemetry (160 events)
- **Sysmon**: 74 events
- **Security**: 36 events
- **Powershell**: 47 events
- **System**: 1 events
- **Application**: 1 events
- **Taskscheduler**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
