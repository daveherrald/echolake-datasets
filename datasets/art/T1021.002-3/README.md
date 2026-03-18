# T1021.002-3: SMB/Windows Admin Shares

**MITRE ATT&CK:** [T1021.002](https://attack.mitre.org/techniques/T1021/002)
**Technique:** SMB/Windows Admin Shares
**Tactic(s):** lateral-movement
**ART Test:** `Invoke-AtomicTest T1021.002 -TestNumbers 3` — Copy and Execute File with PsExec

## Telemetry (55 events)
- **Sysmon**: 16 events
- **Security**: 10 events
- **Powershell**: 29 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
