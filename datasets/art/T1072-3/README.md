# T1072-3: Software Deployment Tools

**MITRE ATT&CK:** [T1072](https://attack.mitre.org/techniques/T1072)
**Technique:** Software Deployment Tools
**Tactic(s):** execution, lateral-movement
**ART Test:** `Invoke-AtomicTest T1072 -TestNumbers 3` — Deploy 7-Zip Using Chocolatey

## Telemetry (78 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
