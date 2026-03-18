# T1546.008-6: Accessibility Features

**MITRE ATT&CK:** [T1546.008](https://attack.mitre.org/techniques/T1546/008)
**Technique:** Accessibility Features
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.008 -TestNumbers 6` — Replace utilman.exe (Ease of Access Binary) with cmd.exe

## Telemetry (79 events)
- **Sysmon**: 29 events
- **Security**: 15 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
