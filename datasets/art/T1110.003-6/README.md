# T1110.003-6: Password Spraying

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003)
**Technique:** Password Spraying
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1110.003 -TestNumbers 6` — Password Spray Invoke-DomainPasswordSpray Light

## Telemetry (85 events)
- **Sysmon**: 27 events
- **Security**: 10 events
- **Powershell**: 48 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
