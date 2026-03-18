# T1059.001-16: PowerShell

**MITRE ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001)
**Technique:** PowerShell
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1059.001 -TestNumbers 16` — ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments

## Telemetry (85 events)
- **Sysmon**: 30 events
- **Security**: 10 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
