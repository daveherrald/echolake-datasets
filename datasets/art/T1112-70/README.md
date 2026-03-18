# T1112-70: Modify Registry

**MITRE ATT&CK:** [T1112](https://attack.mitre.org/techniques/T1112)
**Technique:** Modify Registry
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1112 -TestNumbers 70` — Enable RDP via Registry (fDenyTSConnections)

## Telemetry (60 events)
- **Sysmon**: 22 events
- **Security**: 12 events
- **Powershell**: 26 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
