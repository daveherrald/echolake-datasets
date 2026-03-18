# T1552.004-14: Private Keys

**MITRE ATT&CK:** [T1552.004](https://attack.mitre.org/techniques/T1552/004)
**Technique:** Private Keys
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1552.004 -TestNumbers 14` — Export Certificates with Mimikatz

## Telemetry (62 events)
- **Sysmon**: 17 events
- **Security**: 11 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
