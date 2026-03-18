# T1003.002-4: Security Account Manager

**MITRE ATT&CK:** [T1003.002](https://attack.mitre.org/techniques/T1003/002)
**Technique:** Security Account Manager
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.002 -TestNumbers 4` — PowerDump Hashes and Usernames from Registry

## Telemetry (97 events)
- **Sysmon**: 36 events
- **Security**: 12 events
- **Powershell**: 49 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
