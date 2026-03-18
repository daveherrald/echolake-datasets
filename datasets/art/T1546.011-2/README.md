# T1546.011-2: Application Shimming

**MITRE ATT&CK:** [T1546.011](https://attack.mitre.org/techniques/T1546/011)
**Technique:** Application Shimming
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.011 -TestNumbers 2` — New shim database files created in the default shim database directory

## Telemetry (67 events)
- **Sysmon**: 28 events
- **Security**: 10 events
- **Powershell**: 29 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
