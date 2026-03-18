# T1552.001-12: Credentials In Files

**MITRE ATT&CK:** [T1552.001](https://attack.mitre.org/techniques/T1552/001)
**Technique:** Credentials In Files
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1552.001 -TestNumbers 12` — WinPwn - Loot local Credentials - AWS, Microsoft Azure, and Google Compute credentials

## Telemetry (91 events)
- **Sysmon**: 43 events
- **Security**: 5 events
- **Powershell**: 43 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
