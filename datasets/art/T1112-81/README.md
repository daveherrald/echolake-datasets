# T1112-81: Modify Registry

**MITRE ATT&CK:** [T1112](https://attack.mitre.org/techniques/T1112)
**Technique:** Modify Registry
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1112 -TestNumbers 81` — Modify UseTPMKeyPIN Registry entry

## Telemetry (66 events)
- **Sysmon**: 17 events
- **Security**: 14 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
