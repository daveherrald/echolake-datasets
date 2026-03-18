# T1112-62: Modify Registry

**MITRE ATT&CK:** [T1112](https://attack.mitre.org/techniques/T1112)
**Technique:** Modify Registry
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1112 -TestNumbers 62` — Activities To Disable Microsoft [FIDO Aka Fast IDentity Online] Authentication Detected By Modified Registry Value.

## Telemetry (64 events)
- **Sysmon**: 18 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
