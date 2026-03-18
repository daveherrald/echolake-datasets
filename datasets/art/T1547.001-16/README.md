# T1547.001-16: Registry Run Keys / Startup Folder

**MITRE ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001)
**Technique:** Registry Run Keys / Startup Folder
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.001 -TestNumbers 16` — secedit used to create a Run key in the HKLM Hive

## Telemetry (113 events)
- **Sysmon**: 41 events
- **Security**: 35 events
- **Powershell**: 34 events
- **System**: 1 events
- **Application**: 1 events
- **Taskscheduler**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
