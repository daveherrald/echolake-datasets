# T1087.002-18: Domain Account

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002)
**Technique:** Domain Account
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1087.002 -TestNumbers 18` — Suspicious LAPS Attributes Query with Get-ADComputer all properties

## Telemetry (105 events)
- **Sysmon**: 46 events
- **Security**: 11 events
- **Powershell**: 48 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
