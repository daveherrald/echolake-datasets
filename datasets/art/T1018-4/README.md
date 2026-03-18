# T1018-4: Remote System Discovery

**MITRE ATT&CK:** [T1018](https://attack.mitre.org/techniques/T1018)
**Technique:** Remote System Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1018 -TestNumbers 4` — Remote System Discovery - ping sweep

## Telemetry (880 events)
- **Sysmon**: 286 events
- **Security**: 538 events
- **Powershell**: 54 events
- **Application**: 1 events
- **Taskscheduler**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
