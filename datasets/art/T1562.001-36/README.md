# T1562.001-36: Disable or Modify Tools

**MITRE ATT&CK:** [T1562.001](https://attack.mitre.org/techniques/T1562/001)
**Technique:** Disable or Modify Tools
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.001 -TestNumbers 36` — Disable Windows Defender with PwSh Disable-WindowsOptionalFeature

## Telemetry (153 events)
- **Sysmon**: 40 events
- **Security**: 27 events
- **Powershell**: 79 events
- **System**: 2 events
- **Taskscheduler**: 5 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
