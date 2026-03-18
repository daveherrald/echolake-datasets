# T1016.001-4: Internet Connection Discovery

**MITRE ATT&CK:** [T1016.001](https://attack.mitre.org/techniques/T1016/001)
**Technique:** Internet Connection Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1016.001 -TestNumbers 4` — Check internet connection using Test-NetConnection in PowerShell (TCP-HTTP)

## Telemetry (160 events)
- **Sysmon**: 58 events
- **Security**: 23 events
- **Powershell**: 77 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
