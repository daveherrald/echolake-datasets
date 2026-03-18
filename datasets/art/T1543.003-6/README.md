# T1543.003-6: Windows Service

**MITRE ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003)
**Technique:** Windows Service
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1543.003 -TestNumbers 6` — Modify Service to Run Arbitrary Binary (Powershell)

## Telemetry (111 events)
- **Sysmon**: 46 events
- **Security**: 10 events
- **Powershell**: 55 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
