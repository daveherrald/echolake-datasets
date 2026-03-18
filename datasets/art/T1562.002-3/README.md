# T1562.002-3: Disable Windows Event Logging

**MITRE ATT&CK:** [T1562.002](https://attack.mitre.org/techniques/T1562/002)
**Technique:** Disable Windows Event Logging
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.002 -TestNumbers 3` — Kill Event Log Service Threads

## Telemetry (114 events)
- **Sysmon**: 44 events
- **Security**: 18 events
- **Powershell**: 39 events
- **System**: 5 events
- **Application**: 3 events
- **Wmi**: 1 events
- **Taskscheduler**: 4 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
