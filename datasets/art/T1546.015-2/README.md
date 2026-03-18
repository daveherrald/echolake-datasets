# T1546.015-2: Component Object Model Hijacking

**MITRE ATT&CK:** [T1546.015](https://attack.mitre.org/techniques/T1546/015)
**Technique:** Component Object Model Hijacking
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.015 -TestNumbers 2` — Powershell Execute COM Object

## Telemetry (88 events)
- **Sysmon**: 34 events
- **Security**: 5 events
- **Powershell**: 49 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
