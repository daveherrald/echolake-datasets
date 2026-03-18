# T1055.003-1: Thread Execution Hijacking

**MITRE ATT&CK:** [T1055.003](https://attack.mitre.org/techniques/T1055/003)
**Technique:** Thread Execution Hijacking
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1055.003 -TestNumbers 1` — Thread Execution Hijacking

## Telemetry (89 events)
- **Sysmon**: 31 events
- **Security**: 12 events
- **Powershell**: 46 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
