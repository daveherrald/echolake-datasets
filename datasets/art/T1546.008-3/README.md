# T1546.008-3: Accessibility Features

**MITRE ATT&CK:** [T1546.008](https://attack.mitre.org/techniques/T1546/008)
**Technique:** Accessibility Features
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.008 -TestNumbers 3` — Create Symbolic Link From osk.exe to cmd.exe

## Telemetry (83 events)
- **Sysmon**: 38 events
- **Security**: 10 events
- **Powershell**: 34 events
- **Application**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
