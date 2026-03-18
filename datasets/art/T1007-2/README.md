# T1007-2: System Service Discovery

**MITRE ATT&CK:** [T1007](https://attack.mitre.org/techniques/T1007)
**Technique:** System Service Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1007 -TestNumbers 2` — System Service Discovery - net.exe

## Telemetry (94 events)
- **Sysmon**: 22 events
- **Security**: 24 events
- **Powershell**: 34 events
- **Application**: 1 events
- **Taskscheduler**: 13 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
