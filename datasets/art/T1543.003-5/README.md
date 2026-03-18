# T1543.003-5: Windows Service

**MITRE ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003)
**Technique:** Windows Service
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1543.003 -TestNumbers 5` — Remote Service Installation CMD

## Telemetry (107 events)
- **Sysmon**: 48 events
- **Security**: 15 events
- **Powershell**: 42 events
- **System**: 1 events
- **Application**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
