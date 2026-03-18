# T1123-1: Audio Capture

**MITRE ATT&CK:** [T1123](https://attack.mitre.org/techniques/T1123)
**Technique:** Audio Capture
**Tactic(s):** collection
**ART Test:** `Invoke-AtomicTest T1123 -TestNumbers 1` — using device audio capture commandlet

## Telemetry (108 events)
- **Sysmon**: 46 events
- **Security**: 12 events
- **Powershell**: 50 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
