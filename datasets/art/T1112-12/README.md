# T1112-12: Modify Registry

**MITRE ATT&CK:** [T1112](https://attack.mitre.org/techniques/T1112)
**Technique:** Modify Registry
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1112 -TestNumbers 12` — Disable Windows Task Manager application

## Telemetry (59 events)
- **Sysmon**: 18 events
- **Security**: 15 events
- **Powershell**: 26 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
