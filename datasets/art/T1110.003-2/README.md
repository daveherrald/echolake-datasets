# T1110.003-2: Password Spraying

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003)
**Technique:** Password Spraying
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1110.003 -TestNumbers 2` — Password Spray (DomainPasswordSpray)

## Telemetry (86 events)
- **Sysmon**: 25 events
- **Security**: 9 events
- **Powershell**: 52 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
