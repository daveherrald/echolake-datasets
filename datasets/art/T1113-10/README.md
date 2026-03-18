# T1113-10: Screen Capture

**MITRE ATT&CK:** [T1113](https://attack.mitre.org/techniques/T1113)
**Technique:** Screen Capture
**Tactic(s):** collection
**ART Test:** `Invoke-AtomicTest T1113 -TestNumbers 10` — RDP Bitmap Cache Extraction via bmc-tools

## Telemetry (85 events)
- **Sysmon**: 33 events
- **Security**: 13 events
- **Powershell**: 39 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
