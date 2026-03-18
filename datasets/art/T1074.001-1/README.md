# T1074.001-1: Local Data Staging

**MITRE ATT&CK:** [T1074.001](https://attack.mitre.org/techniques/T1074/001)
**Technique:** Local Data Staging
**Tactic(s):** collection
**ART Test:** `Invoke-AtomicTest T1074.001 -TestNumbers 1` — Stage data from Discovery.bat

## Telemetry (83 events)
- **Sysmon**: 36 events
- **Security**: 8 events
- **Powershell**: 39 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
