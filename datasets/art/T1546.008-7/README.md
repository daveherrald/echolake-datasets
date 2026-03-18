# T1546.008-7: Accessibility Features

**MITRE ATT&CK:** [T1546.008](https://attack.mitre.org/techniques/T1546/008)
**Technique:** Accessibility Features
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.008 -TestNumbers 7` — Replace Magnify.exe (Magnifier binary) with cmd.exe

## Telemetry (68 events)
- **Sysmon**: 21 events
- **Security**: 21 events
- **Powershell**: 26 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
