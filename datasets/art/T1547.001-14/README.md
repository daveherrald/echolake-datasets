# T1547.001-14: Registry Run Keys / Startup Folder

**MITRE ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001)
**Technique:** Registry Run Keys / Startup Folder
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.001 -TestNumbers 14` — HKLM - Append Command to Winlogon Userinit KEY Value

## Telemetry (111 events)
- **Sysmon**: 48 events
- **Security**: 10 events
- **Powershell**: 53 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
