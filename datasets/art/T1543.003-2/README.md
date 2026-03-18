# T1543.003-2: Windows Service

**MITRE ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003)
**Technique:** Windows Service
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1543.003 -TestNumbers 2` — Service Installation CMD

## Telemetry (87 events)
- **Sysmon**: 36 events
- **Security**: 15 events
- **Powershell**: 34 events
- **System**: 1 events
- **Application**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
