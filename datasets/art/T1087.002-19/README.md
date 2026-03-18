# T1087.002-19: Domain Account

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002)
**Technique:** Domain Account
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1087.002 -TestNumbers 19` — Suspicious LAPS Attributes Query with Get-ADComputer ms-Mcs-AdmPwd property

## Telemetry (101 events)
- **Sysmon**: 46 events
- **Security**: 10 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
