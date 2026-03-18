# T1555.004-2: Windows Credential Manager

**MITRE ATT&CK:** [T1555.004](https://attack.mitre.org/techniques/T1555/004)
**Technique:** Windows Credential Manager
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1555.004 -TestNumbers 2` — WinPwn - Loot local Credentials - Invoke-WCMDump

## Telemetry (83 events)
- **Sysmon**: 33 events
- **Security**: 9 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
