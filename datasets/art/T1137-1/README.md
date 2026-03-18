# T1137-1: Office Application Startup

**MITRE ATT&CK:** [T1137](https://attack.mitre.org/techniques/T1137)
**Technique:** Office Application Startup
**Tactic(s):** persistence
**ART Test:** `Invoke-AtomicTest T1137 -TestNumbers 1` — Office Application Startup - Outlook as a C2

## Telemetry (75 events)
- **Sysmon**: 29 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
