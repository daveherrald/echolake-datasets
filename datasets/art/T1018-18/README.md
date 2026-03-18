# T1018-18: Remote System Discovery

**MITRE ATT&CK:** [T1018](https://attack.mitre.org/techniques/T1018)
**Technique:** Remote System Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1018 -TestNumbers 18` — Enumerate Active Directory Computers with ADSISearcher

## Telemetry (73 events)
- **Sysmon**: 29 events
- **Security**: 15 events
- **Powershell**: 29 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
