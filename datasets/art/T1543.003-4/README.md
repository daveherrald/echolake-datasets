# T1543.003-4: Windows Service

**MITRE ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003)
**Technique:** Windows Service
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1543.003 -TestNumbers 4` — TinyTurla backdoor service w64time

## Telemetry (115 events)
- **Sysmon**: 51 events
- **Security**: 28 events
- **Powershell**: 34 events
- **System**: 2 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
