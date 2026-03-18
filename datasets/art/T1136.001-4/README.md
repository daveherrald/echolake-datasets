# T1136.001-4: Local Account

**MITRE ATT&CK:** [T1136.001](https://attack.mitre.org/techniques/T1136/001)
**Technique:** Local Account
**Tactic(s):** persistence
**ART Test:** `Invoke-AtomicTest T1136.001 -TestNumbers 4` — Create a new user in a command prompt

## Telemetry (78 events)
- **Sysmon**: 28 events
- **Security**: 16 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
