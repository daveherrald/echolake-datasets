# T1021.002-2: SMB/Windows Admin Shares

**MITRE ATT&CK:** [T1021.002](https://attack.mitre.org/techniques/T1021/002)
**Technique:** SMB/Windows Admin Shares
**Tactic(s):** lateral-movement
**ART Test:** `Invoke-AtomicTest T1021.002 -TestNumbers 2` — Map Admin Share PowerShell

## Telemetry (130 events)
- **Sysmon**: 47 events
- **Security**: 17 events
- **Powershell**: 66 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
