# T1021.002-1: SMB/Windows Admin Shares

**MITRE ATT&CK:** [T1021.002](https://attack.mitre.org/techniques/T1021/002)
**Technique:** SMB/Windows Admin Shares
**Tactic(s):** lateral-movement
**ART Test:** `Invoke-AtomicTest T1021.002 -TestNumbers 1` — Map admin share

## Telemetry (78 events)
- **Sysmon**: 30 events
- **Security**: 14 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
