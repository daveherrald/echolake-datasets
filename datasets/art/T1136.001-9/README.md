# T1136.001-9: Local Account

**MITRE ATT&CK:** [T1136.001](https://attack.mitre.org/techniques/T1136/001)
**Technique:** Local Account
**Tactic(s):** persistence
**ART Test:** `Invoke-AtomicTest T1136.001 -TestNumbers 9` — Create a new Windows admin user via .NET

## Telemetry (126 events)
- **Sysmon**: 62 events
- **Security**: 16 events
- **Powershell**: 48 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
