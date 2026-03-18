# T1112-11: Modify Registry

**MITRE ATT&CK:** [T1112](https://attack.mitre.org/techniques/T1112)
**Technique:** Modify Registry
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1112 -TestNumbers 11` — Disable Windows CMD application

## Telemetry (90 events)
- **Sysmon**: 35 events
- **Security**: 8 events
- **Powershell**: 47 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
