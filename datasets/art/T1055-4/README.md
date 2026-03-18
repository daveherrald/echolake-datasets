# T1055-4: Process Injection

**MITRE ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055)
**Technique:** Process Injection
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1055 -TestNumbers 4` — Dirty Vanity process Injection

## Telemetry (112 events)
- **Sysmon**: 47 events
- **Security**: 18 events
- **Powershell**: 47 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
