# T1518.001-8: Security Software Discovery

**MITRE ATT&CK:** [T1518.001](https://attack.mitre.org/techniques/T1518/001)
**Technique:** Security Software Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1518.001 -TestNumbers 8` — Security Software Discovery - AV Discovery via Get-CimInstance and Get-WmiObject cmdlets

## Telemetry (140 events)
- **Sysmon**: 59 events
- **Security**: 17 events
- **Powershell**: 64 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
