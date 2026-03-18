# T1074.001-3: Local Data Staging

**MITRE ATT&CK:** [T1074.001](https://attack.mitre.org/techniques/T1074/001)
**Technique:** Local Data Staging
**Tactic(s):** collection
**ART Test:** `Invoke-AtomicTest T1074.001 -TestNumbers 3` — Zip a Folder with PowerShell for Staging in Temp

## Telemetry (76 events)
- **Sysmon**: 27 events
- **Security**: 10 events
- **Powershell**: 38 events
- **Application**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
