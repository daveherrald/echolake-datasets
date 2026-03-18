# T1033-4: System Owner/User Discovery

**MITRE ATT&CK:** [T1033](https://attack.mitre.org/techniques/T1033)
**Technique:** System Owner/User Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1033 -TestNumbers 4` — User Discovery With Env Vars PowerShell Script

## Telemetry (89 events)
- **Sysmon**: 37 events
- **Security**: 13 events
- **Powershell**: 39 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
