# T1049-3: System Network Connections Discovery

**MITRE ATT&CK:** [T1049](https://attack.mitre.org/techniques/T1049)
**Technique:** System Network Connections Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1049 -TestNumbers 3` — System Network Connections Discovery via PowerShell (Process Mapping)

## Telemetry (171 events)
- **Sysmon**: 39 events
- **Security**: 21 events
- **Powershell**: 105 events
- **System**: 1 events
- **Taskscheduler**: 5 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
