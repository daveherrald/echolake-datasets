# T1552.004-11: Private Keys

**MITRE ATT&CK:** [T1552.004](https://attack.mitre.org/techniques/T1552/004)
**Technique:** Private Keys
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1552.004 -TestNumbers 11` — CertUtil ExportPFX

## Telemetry (182 events)
- **Sysmon**: 60 events
- **Security**: 47 events
- **Powershell**: 66 events
- **Application**: 1 events
- **Taskscheduler**: 8 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
