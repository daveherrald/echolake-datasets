# T1039-1: Data from Network Shared Drive

**MITRE ATT&CK:** [T1039](https://attack.mitre.org/techniques/T1039)
**Technique:** Data from Network Shared Drive
**Tactic(s):** collection
**ART Test:** `Invoke-AtomicTest T1039 -TestNumbers 1` — Copy a sensitive File over Administrative share with copy

## Telemetry (83 events)
- **Sysmon**: 36 events
- **Security**: 13 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
