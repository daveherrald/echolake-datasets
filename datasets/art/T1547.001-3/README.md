# T1547.001-3: Registry Run Keys / Startup Folder

**MITRE ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001)
**Technique:** Registry Run Keys / Startup Folder
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.001 -TestNumbers 3` — PowerShell Registry RunOnce

## Telemetry (79 events)
- **Sysmon**: 29 events
- **Security**: 12 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
