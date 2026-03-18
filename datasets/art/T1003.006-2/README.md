# T1003.006-2: DCSync

**MITRE ATT&CK:** [T1003.006](https://attack.mitre.org/techniques/T1003/006)
**Technique:** DCSync
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.006 -TestNumbers 2` — Run DSInternals Get-ADReplAccount

## Telemetry (82 events)
- **Sysmon**: 26 events
- **Security**: 11 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
