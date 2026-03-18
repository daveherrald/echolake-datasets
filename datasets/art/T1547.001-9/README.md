# T1547.001-9: Registry Run Keys / Startup Folder

**MITRE ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001)
**Technique:** Registry Run Keys / Startup Folder
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.001 -TestNumbers 9` — SystemBC Malware-as-a-Service Registry

## Telemetry (85 events)
- **Sysmon**: 37 events
- **Security**: 10 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
