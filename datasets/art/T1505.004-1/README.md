# T1505.004-1: IIS Components

**MITRE ATT&CK:** [T1505.004](https://attack.mitre.org/techniques/T1505/004)
**Technique:** IIS Components
**Tactic(s):** persistence
**ART Test:** `Invoke-AtomicTest T1505.004 -TestNumbers 1` — Install IIS Module using AppCmd.exe

## Telemetry (81 events)
- **Sysmon**: 35 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
