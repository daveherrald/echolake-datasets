# T1018-16: Remote System Discovery

**MITRE ATT&CK:** [T1018](https://attack.mitre.org/techniques/T1018)
**Technique:** Remote System Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1018 -TestNumbers 16` — Enumerate domain computers within Active Directory using DirectorySearcher

## Telemetry (82 events)
- **Sysmon**: 28 events
- **Security**: 10 events
- **Powershell**: 44 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
