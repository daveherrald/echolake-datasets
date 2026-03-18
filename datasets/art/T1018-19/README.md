# T1018-19: Remote System Discovery

**MITRE ATT&CK:** [T1018](https://attack.mitre.org/techniques/T1018)
**Technique:** Remote System Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1018 -TestNumbers 19` — Get-DomainController with PowerView

## Telemetry (65 events)
- **Sysmon**: 15 events
- **Security**: 9 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
