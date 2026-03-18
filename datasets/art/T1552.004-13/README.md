# T1552.004-13: Private Keys

**MITRE ATT&CK:** [T1552.004](https://attack.mitre.org/techniques/T1552/004)
**Technique:** Private Keys
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1552.004 -TestNumbers 13` — Export Root Certificate with Export-Certificate

## Telemetry (83 events)
- **Sysmon**: 30 events
- **Security**: 16 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
