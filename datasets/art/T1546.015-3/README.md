# T1546.015-3: Component Object Model Hijacking

**MITRE ATT&CK:** [T1546.015](https://attack.mitre.org/techniques/T1546/015)
**Technique:** Component Object Model Hijacking
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.015 -TestNumbers 3` — COM Hijacking with RunDLL32 (Local Server Switch)

## Telemetry (98 events)
- **Sysmon**: 50 events
- **Security**: 11 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
