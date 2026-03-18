# T1005-1: Data from Local System

**MITRE ATT&CK:** [T1005](https://attack.mitre.org/techniques/T1005)
**Technique:** Data from Local System
**Tactic(s):** collection
**ART Test:** `Invoke-AtomicTest T1005 -TestNumbers 1` — Search files of interest and save them to a single zip file (Windows)

## Telemetry (76 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 40 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
