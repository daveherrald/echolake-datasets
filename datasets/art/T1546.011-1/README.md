# T1546.011-1: Application Shimming

**MITRE ATT&CK:** [T1546.011](https://attack.mitre.org/techniques/T1546/011)
**Technique:** Application Shimming
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.011 -TestNumbers 1` — Application Shim Installation

## Telemetry (73 events)
- **Sysmon**: 26 events
- **Security**: 13 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
