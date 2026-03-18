# T1112-40: Modify Registry

**MITRE ATT&CK:** [T1112](https://attack.mitre.org/techniques/T1112)
**Technique:** Modify Registry
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1112 -TestNumbers 40` — NetWire RAT Registry Key Creation

## Telemetry (98 events)
- **Sysmon**: 40 events
- **Security**: 16 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
