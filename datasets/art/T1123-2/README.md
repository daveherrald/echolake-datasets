# T1123-2: Audio Capture

**MITRE ATT&CK:** [T1123](https://attack.mitre.org/techniques/T1123)
**Technique:** Audio Capture
**Tactic(s):** collection
**ART Test:** `Invoke-AtomicTest T1123 -TestNumbers 2` — Registry artefact when application use microphone

## Telemetry (61 events)
- **Sysmon**: 25 events
- **Security**: 14 events
- **Powershell**: 22 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
