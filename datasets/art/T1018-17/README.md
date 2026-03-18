# T1018-17: Remote System Discovery

**MITRE ATT&CK:** [T1018](https://attack.mitre.org/techniques/T1018)
**Technique:** Remote System Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1018 -TestNumbers 17` — Enumerate Active Directory Computers with Get-AdComputer

## Telemetry (83 events)
- **Sysmon**: 26 events
- **Security**: 12 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
