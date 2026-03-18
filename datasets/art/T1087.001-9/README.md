# T1087.001-9: Local Account

**MITRE ATT&CK:** [T1087.001](https://attack.mitre.org/techniques/T1087/001)
**Technique:** Local Account
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1087.001 -TestNumbers 9` — Enumerate all accounts via PowerShell (Local)

## Telemetry (119 events)
- **Sysmon**: 55 events
- **Security**: 21 events
- **Powershell**: 43 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
