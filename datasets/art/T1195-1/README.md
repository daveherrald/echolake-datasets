# T1195-1: Supply Chain Compromise

**MITRE ATT&CK:** [T1195](https://attack.mitre.org/techniques/T1195)
**Technique:** Supply Chain Compromise
**Tactic(s):** initial-access
**ART Test:** `Invoke-AtomicTest T1195 -TestNumbers 1` — Octopus Scanner Malware Open Source Supply Chain

## Telemetry (75 events)
- **Sysmon**: 23 events
- **Security**: 13 events
- **Powershell**: 35 events
- **Application**: 1 events
- **Taskscheduler**: 3 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
