# T1113-7: Screen Capture

**MITRE ATT&CK:** [T1113](https://attack.mitre.org/techniques/T1113)
**Technique:** Screen Capture
**Tactic(s):** collection
**ART Test:** `Invoke-AtomicTest T1113 -TestNumbers 7` — Windows Screencapture

## Telemetry (121 events)
- **Sysmon**: 35 events
- **Security**: 29 events
- **Powershell**: 55 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
