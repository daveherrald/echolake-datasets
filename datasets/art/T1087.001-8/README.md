# T1087.001-8: Local Account

**MITRE ATT&CK:** [T1087.001](https://attack.mitre.org/techniques/T1087/001)
**Technique:** Local Account
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1087.001 -TestNumbers 8` — Enumerate all accounts on Windows (Local)

## Telemetry (110 events)
- **Sysmon**: 44 events
- **Security**: 24 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
