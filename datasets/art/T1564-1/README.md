# T1564-1: Hide Artifacts

**MITRE ATT&CK:** [T1564](https://attack.mitre.org/techniques/T1564)
**Technique:** Hide Artifacts
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1564 -TestNumbers 1` — Extract binary files via VBA

## Telemetry (95 events)
- **Sysmon**: 2 events
- **Security**: 10 events
- **Powershell**: 83 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
