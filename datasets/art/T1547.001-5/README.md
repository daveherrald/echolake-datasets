# T1547.001-5: Registry Run Keys / Startup Folder

**MITRE ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001)
**Technique:** Registry Run Keys / Startup Folder
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.001 -TestNumbers 5` — Suspicious jse file run from startup Folder

## Telemetry (97 events)
- **Sysmon**: 46 events
- **Security**: 14 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
