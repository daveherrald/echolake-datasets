# T1552.001-13: Credentials In Files

**MITRE ATT&CK:** [T1552.001](https://attack.mitre.org/techniques/T1552/001)
**Technique:** Credentials In Files
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1552.001 -TestNumbers 13` — List Credential Files via PowerShell

## Telemetry (117 events)
- **Sysmon**: 46 events
- **Security**: 10 events
- **Powershell**: 60 events
- **Application**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
