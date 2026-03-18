# T1562.001-28: Disable or Modify Tools

**MITRE ATT&CK:** [T1562.001](https://attack.mitre.org/techniques/T1562/001)
**Technique:** Disable or Modify Tools
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.001 -TestNumbers 28` — Disable Defender Using NirSoft AdvancedRun

## Telemetry (73 events)
- **Sysmon**: 19 events
- **Security**: 10 events
- **Powershell**: 41 events
- **Taskscheduler**: 3 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
