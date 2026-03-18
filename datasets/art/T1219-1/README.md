# T1219-1: Remote Access Tools

**MITRE ATT&CK:** [T1219](https://attack.mitre.org/techniques/T1219)
**Technique:** Remote Access Tools
**Tactic(s):** command-and-control
**ART Test:** `Invoke-AtomicTest T1219 -TestNumbers 1` — TeamViewer Files Detected Test on Windows

## Telemetry (107 events)
- **Sysmon**: 38 events
- **Security**: 10 events
- **Powershell**: 59 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
