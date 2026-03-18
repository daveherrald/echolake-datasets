# T1059.001-13: PowerShell

**MITRE ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001)
**Technique:** PowerShell
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1059.001 -TestNumbers 13` — ATHPowerShellCommandLineParameter -Command parameter variations

## Telemetry (101 events)
- **Sysmon**: 37 events
- **Security**: 13 events
- **Powershell**: 45 events
- **Taskscheduler**: 6 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
