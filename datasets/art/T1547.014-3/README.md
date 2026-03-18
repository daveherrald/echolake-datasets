# T1547.014-3: Active Setup

**MITRE ATT&CK:** [T1547.014](https://attack.mitre.org/techniques/T1547/014)
**Technique:** Active Setup
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.014 -TestNumbers 3` — HKLM - re-execute 'Internet Explorer Core Fonts' StubPath payload by decreasing version number

## Telemetry (99 events)
- **Sysmon**: 49 events
- **Security**: 12 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
