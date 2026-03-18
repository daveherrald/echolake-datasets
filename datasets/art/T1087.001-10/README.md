# T1087.001-10: Local Account

**MITRE ATT&CK:** [T1087.001](https://attack.mitre.org/techniques/T1087/001)
**Technique:** Local Account
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1087.001 -TestNumbers 10` — Enumerate logged on users via CMD (Local)

## Telemetry (94 events)
- **Sysmon**: 38 events
- **Security**: 14 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
