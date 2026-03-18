# T1039-2: Data from Network Shared Drive

**MITRE ATT&CK:** [T1039](https://attack.mitre.org/techniques/T1039)
**Technique:** Data from Network Shared Drive
**Tactic(s):** collection
**ART Test:** `Invoke-AtomicTest T1039 -TestNumbers 2` — Copy a sensitive File over Administrative share with Powershell

## Telemetry (99 events)
- **Sysmon**: 43 events
- **Security**: 10 events
- **Powershell**: 46 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
