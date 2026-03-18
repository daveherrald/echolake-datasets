# T1113-8: Screen Capture

**MITRE ATT&CK:** [T1113](https://attack.mitre.org/techniques/T1113)
**Technique:** Screen Capture
**Tactic(s):** collection
**ART Test:** `Invoke-AtomicTest T1113 -TestNumbers 8` — Windows Screen Capture (CopyFromScreen)

## Telemetry (94 events)
- **Sysmon**: 37 events
- **Security**: 10 events
- **Powershell**: 47 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
