# T1112-71: Modify Registry

**MITRE ATT&CK:** [T1112](https://attack.mitre.org/techniques/T1112)
**Technique:** Modify Registry
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1112 -TestNumbers 71` — Disable Windows Prefetch Through Registry

## Telemetry (91 events)
- **Sysmon**: 37 events
- **Security**: 12 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
