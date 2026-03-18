# T1087.002-22: Domain Account

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002)
**Technique:** Domain Account
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1087.002 -TestNumbers 22` — Suspicious LAPS Attributes Query with adfind ms-Mcs-AdmPwd

## Telemetry (89 events)
- **Sysmon**: 32 events
- **Security**: 12 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
