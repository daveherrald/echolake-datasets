# T1091-1: Replication Through Removable Media

**MITRE ATT&CK:** [T1091](https://attack.mitre.org/techniques/T1091)
**Technique:** Replication Through Removable Media
**Tactic(s):** initial-access, lateral-movement
**ART Test:** `Invoke-AtomicTest T1091 -TestNumbers 1` — USB Malware Spread Simulation

## Telemetry (108 events)
- **Sysmon**: 48 events
- **Security**: 20 events
- **Powershell**: 40 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
