# T1003.002-5: Security Account Manager

**MITRE ATT&CK:** [T1003.002](https://attack.mitre.org/techniques/T1003/002)
**Technique:** Security Account Manager
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.002 -TestNumbers 5` — dump volume shadow copy hives with certutil

## Telemetry (100 events)
- **Sysmon**: 36 events
- **Security**: 30 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
