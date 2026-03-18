# T1003.002-7: Security Account Manager

**MITRE ATT&CK:** [T1003.002](https://attack.mitre.org/techniques/T1003/002)
**Technique:** Security Account Manager
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.002 -TestNumbers 7` — WinPwn - Loot local Credentials - Dump SAM-File for NTLM Hashes

## Telemetry (100 events)
- **Sysmon**: 39 events
- **Security**: 10 events
- **Powershell**: 51 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
