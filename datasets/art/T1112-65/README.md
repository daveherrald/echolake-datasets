# T1112-65: Modify Registry

**MITRE ATT&CK:** [T1112](https://attack.mitre.org/techniques/T1112)
**Technique:** Modify Registry
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1112 -TestNumbers 65` — Disable Remote Desktop Security Settings Through Registry

## Telemetry (75 events)
- **Sysmon**: 27 events
- **Security**: 13 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
