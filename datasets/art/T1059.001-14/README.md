# T1059.001-14: PowerShell

**MITRE ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001)
**Technique:** PowerShell
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1059.001 -TestNumbers 14` — ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments

## Telemetry (84 events)
- **Sysmon**: 26 events
- **Security**: 13 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
