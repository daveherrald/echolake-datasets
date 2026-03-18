# T1552.006-2: Group Policy Preferences

**MITRE ATT&CK:** [T1552.006](https://attack.mitre.org/techniques/T1552/006)
**Technique:** Group Policy Preferences
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1552.006 -TestNumbers 2` — GPP Passwords (Get-GPPPassword)

## Telemetry (95 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 49 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
