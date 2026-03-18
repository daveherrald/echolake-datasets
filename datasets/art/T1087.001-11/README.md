# T1087.001-11: Local Account

**MITRE ATT&CK:** [T1087.001](https://attack.mitre.org/techniques/T1087/001)
**Technique:** Local Account
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1087.001 -TestNumbers 11` — ESXi - Local Account Discovery via ESXCLI

## Telemetry (75 events)
- **Sysmon**: 27 events
- **Security**: 14 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
