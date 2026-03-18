# T1482-7: Domain Trust Discovery

**MITRE ATT&CK:** [T1482](https://attack.mitre.org/techniques/T1482)
**Technique:** Domain Trust Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1482 -TestNumbers 7` — Get-ForestTrust with PowerView

## Telemetry (61 events)
- **Sysmon**: 20 events
- **Security**: 12 events
- **Powershell**: 29 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
