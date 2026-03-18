# T1125-1: Video Capture

**MITRE ATT&CK:** [T1125](https://attack.mitre.org/techniques/T1125)
**Technique:** Video Capture
**Tactic(s):** collection
**ART Test:** `Invoke-AtomicTest T1125 -TestNumbers 1` — Registry artefact when application use webcam

## Telemetry (80 events)
- **Sysmon**: 30 events
- **Security**: 15 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
