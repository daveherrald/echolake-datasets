# T1562.001-29: Disable or Modify Tools

**MITRE ATT&CK:** [T1562.001](https://attack.mitre.org/techniques/T1562/001)
**Technique:** Disable or Modify Tools
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.001 -TestNumbers 29` — Kill antimalware protected processes using Backstab

## Telemetry (104 events)
- **Sysmon**: 46 events
- **Security**: 11 events
- **Powershell**: 45 events
- **Application**: 1 events
- **Taskscheduler**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
