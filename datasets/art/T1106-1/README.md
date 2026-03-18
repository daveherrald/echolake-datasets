# T1106-1: Native API

**MITRE ATT&CK:** [T1106](https://attack.mitre.org/techniques/T1106)
**Technique:** Native API
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1106 -TestNumbers 1` — Execution through API - CreateProcess

## Telemetry (80 events)
- **Sysmon**: 32 events
- **Security**: 21 events
- **Powershell**: 27 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
