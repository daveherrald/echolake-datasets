# T1055-13: Process Injection

**MITRE ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055)
**Technique:** Process Injection
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1055 -TestNumbers 13` — UUID custom process Injection

## Telemetry (109 events)
- **Sysmon**: 47 events
- **Security**: 16 events
- **Powershell**: 46 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
