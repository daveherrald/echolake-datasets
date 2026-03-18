# T1219-2: Remote Access Tools

**MITRE ATT&CK:** [T1219](https://attack.mitre.org/techniques/T1219)
**Technique:** Remote Access Tools
**Tactic(s):** command-and-control
**ART Test:** `Invoke-AtomicTest T1219 -TestNumbers 2` — AnyDesk Files Detected Test on Windows

## Telemetry (100 events)
- **Sysmon**: 37 events
- **Security**: 10 events
- **Powershell**: 53 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
