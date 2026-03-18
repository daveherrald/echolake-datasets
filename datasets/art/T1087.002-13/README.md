# T1087.002-13: Domain Account

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002)
**Technique:** Domain Account
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1087.002 -TestNumbers 13` — Enumerate Linked Policies In ADSISearcher Discovery

## Telemetry (80 events)
- **Sysmon**: 27 events
- **Security**: 10 events
- **Powershell**: 43 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
