# T1555.004-1: Windows Credential Manager

**MITRE ATT&CK:** [T1555.004](https://attack.mitre.org/techniques/T1555/004)
**Technique:** Windows Credential Manager
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1555.004 -TestNumbers 1` — Access Saved Credentials via VaultCmd

## Telemetry (73 events)
- **Sysmon**: 27 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
