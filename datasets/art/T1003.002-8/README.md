# T1003.002-8: Security Account Manager

**MITRE ATT&CK:** [T1003.002](https://attack.mitre.org/techniques/T1003/002)
**Technique:** Security Account Manager
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.002 -TestNumbers 8` — Dumping of SAM, creds, and secrets(Reg Export)

## Telemetry (76 events)
- **Sysmon**: 27 events
- **Security**: 14 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
