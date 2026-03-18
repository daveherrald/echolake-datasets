# T1110.003-1: Password Spraying

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003)
**Technique:** Password Spraying
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1110.003 -TestNumbers 1` — Password Spray all Domain Users

## Telemetry (66 events)
- **Sysmon**: 22 events
- **Security**: 10 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
