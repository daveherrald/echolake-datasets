# T1033-5: System Owner/User Discovery

**MITRE ATT&CK:** [T1033](https://attack.mitre.org/techniques/T1033)
**Technique:** System Owner/User Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1033 -TestNumbers 5` — GetCurrent User with PowerShell Script

## Telemetry (85 events)
- **Sysmon**: 37 events
- **Security**: 10 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
