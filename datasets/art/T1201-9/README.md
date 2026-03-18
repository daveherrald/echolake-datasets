# T1201-9: Password Policy Discovery

**MITRE ATT&CK:** [T1201](https://attack.mitre.org/techniques/T1201)
**Technique:** Password Policy Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1201 -TestNumbers 9` — Get-DomainPolicy with PowerView

## Telemetry (75 events)
- **Sysmon**: 25 events
- **Security**: 9 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
