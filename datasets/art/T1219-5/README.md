# T1219-5: Remote Access Tools

**MITRE ATT&CK:** [T1219](https://attack.mitre.org/techniques/T1219)
**Technique:** Remote Access Tools
**Tactic(s):** command-and-control
**ART Test:** `Invoke-AtomicTest T1219 -TestNumbers 5` — ScreenConnect Application Download and Install on Windows

## Telemetry (110 events)
- **Sysmon**: 40 events
- **Security**: 20 events
- **Powershell**: 48 events
- **Application**: 2 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
