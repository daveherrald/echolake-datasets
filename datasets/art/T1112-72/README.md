# T1112-72: Modify Registry

**MITRE ATT&CK:** [T1112](https://attack.mitre.org/techniques/T1112)
**Technique:** Modify Registry
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1112 -TestNumbers 72` — Setting Shadow key in Registry for RDP Shadowing

## Telemetry (116 events)
- **Sysmon**: 40 events
- **Security**: 11 events
- **Powershell**: 65 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
