# T1562.001-58: Disable or Modify Tools

**MITRE ATT&CK:** [T1562.001](https://attack.mitre.org/techniques/T1562/001)
**Technique:** Disable or Modify Tools
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.001 -TestNumbers 58` — Freeze PPL-protected process with EDR-Freeze

## Telemetry (113 events)
- **Sysmon**: 4 events
- **Security**: 24 events
- **Powershell**: 85 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
