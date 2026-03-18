# T1562.001-11: Disable or Modify Tools

**MITRE ATT&CK:** [T1562.001](https://attack.mitre.org/techniques/T1562/001)
**Technique:** Disable or Modify Tools
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.001 -TestNumbers 11` — Unload Sysmon Filter Driver

## Telemetry (75 events)
- **Sysmon**: 27 events
- **Security**: 13 events
- **Powershell**: 34 events
- **System**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
