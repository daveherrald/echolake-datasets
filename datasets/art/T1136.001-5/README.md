# T1136.001-5: Local Account

**MITRE ATT&CK:** [T1136.001](https://attack.mitre.org/techniques/T1136/001)
**Technique:** Local Account
**Tactic(s):** persistence
**ART Test:** `Invoke-AtomicTest T1136.001 -TestNumbers 5` — Create a new user in PowerShell

## Telemetry (86 events)
- **Sysmon**: 37 events
- **Security**: 11 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
