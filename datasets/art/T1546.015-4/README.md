# T1546.015-4: Component Object Model Hijacking

**MITRE ATT&CK:** [T1546.015](https://attack.mitre.org/techniques/T1546/015)
**Technique:** Component Object Model Hijacking
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.015 -TestNumbers 4` — COM hijacking via TreatAs

## Telemetry (137 events)
- **Sysmon**: 66 events
- **Security**: 38 events
- **Powershell**: 33 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
