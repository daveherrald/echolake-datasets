# T1505.004-2: IIS Components

**MITRE ATT&CK:** [T1505.004](https://attack.mitre.org/techniques/T1505/004)
**Technique:** IIS Components
**Tactic(s):** persistence
**ART Test:** `Invoke-AtomicTest T1505.004 -TestNumbers 2` — Install IIS Module using PowerShell Cmdlet New-WebGlobalModule

## Telemetry (101 events)
- **Sysmon**: 46 events
- **Security**: 10 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
