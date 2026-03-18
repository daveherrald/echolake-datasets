# T1571-1: Non-Standard Port

**MITRE ATT&CK:** [T1571](https://attack.mitre.org/techniques/T1571)
**Technique:** Non-Standard Port
**Tactic(s):** command-and-control
**ART Test:** `Invoke-AtomicTest T1571 -TestNumbers 1` — Testing usage of uncommonly used port with PowerShell

## Telemetry (103 events)
- **Sysmon**: 3 events
- **Security**: 17 events
- **Powershell**: 83 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
