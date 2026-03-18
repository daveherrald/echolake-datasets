# T1136.001-8: Local Account

**MITRE ATT&CK:** [T1136.001](https://attack.mitre.org/techniques/T1136/001)
**Technique:** Local Account
**Tactic(s):** persistence
**ART Test:** `Invoke-AtomicTest T1136.001 -TestNumbers 8` — Create a new Windows admin user

## Telemetry (75 events)
- **Sysmon**: 23 events
- **Security**: 18 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
