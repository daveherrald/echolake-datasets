# T1016.001-5: Internet Connection Discovery

**MITRE ATT&CK:** [T1016.001](https://attack.mitre.org/techniques/T1016/001)
**Technique:** Internet Connection Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1016.001 -TestNumbers 5` — Check internet connection using Test-NetConnection in PowerShell (TCP-SMB)

## Telemetry (137 events)
- **Sysmon**: 37 events
- **Security**: 18 events
- **Powershell**: 82 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
