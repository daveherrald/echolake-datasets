# T1021.002-4: SMB/Windows Admin Shares

**MITRE ATT&CK:** [T1021.002](https://attack.mitre.org/techniques/T1021/002)
**Technique:** SMB/Windows Admin Shares
**Tactic(s):** lateral-movement
**ART Test:** `Invoke-AtomicTest T1021.002 -TestNumbers 4` — Execute command writing output to local Admin Share

## Telemetry (66 events)
- **Sysmon**: 18 events
- **Security**: 14 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
