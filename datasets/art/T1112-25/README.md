# T1112-25: Modify Registry

**MITRE ATT&CK:** [T1112](https://attack.mitre.org/techniques/T1112)
**Technique:** Modify Registry
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1112 -TestNumbers 25` — Activate Windows NoTrayContextMenu Group Policy Feature

## Telemetry (61 events)
- **Sysmon**: 17 events
- **Security**: 12 events
- **Powershell**: 32 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
