# T1552-2: Unsecured Credentials

**MITRE ATT&CK:** [T1552](https://attack.mitre.org/techniques/T1552)
**Technique:** Unsecured Credentials
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1552 -TestNumbers 2` — Search for Passwords in Powershell History

## Telemetry (71 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
