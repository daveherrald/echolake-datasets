# T1069.002-12: Domain Groups

**MITRE ATT&CK:** [T1069.002](https://attack.mitre.org/techniques/T1069/002)
**Technique:** Domain Groups
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1069.002 -TestNumbers 12` — Get-DomainGroupMember with PowerView

## Telemetry (65 events)
- **Sysmon**: 15 events
- **Security**: 9 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
