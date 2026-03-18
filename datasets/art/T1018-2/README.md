# T1018-2: Remote System Discovery

**MITRE ATT&CK:** [T1018](https://attack.mitre.org/techniques/T1018)
**Technique:** Remote System Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1018 -TestNumbers 2` — Remote System Discovery - net group Domain Computers

## Telemetry (68 events)
- **Sysmon**: 18 events
- **Security**: 15 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
