# T1113-9: Screen Capture

**MITRE ATT&CK:** [T1113](https://attack.mitre.org/techniques/T1113)
**Technique:** Screen Capture
**Tactic(s):** collection
**ART Test:** `Invoke-AtomicTest T1113 -TestNumbers 9` — Windows Recall Feature Enabled - DisableAIDataAnalysis Value Deleted

## Telemetry (73 events)
- **Sysmon**: 30 events
- **Security**: 15 events
- **Powershell**: 28 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
