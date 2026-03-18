# T1003.006-1: DCSync

**MITRE ATT&CK:** [T1003.006](https://attack.mitre.org/techniques/T1003/006)
**Technique:** DCSync
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.006 -TestNumbers 1` — DCSync via mimikatz

## Telemetry (93 events)
- **Sysmon**: 37 events
- **Security**: 15 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
