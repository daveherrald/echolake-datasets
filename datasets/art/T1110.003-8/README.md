# T1110.003-8: Password Spraying

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003)
**Technique:** Password Spraying
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1110.003 -TestNumbers 8` — Password Spray using Kerbrute Tool

## Telemetry (81 events)
- **Sysmon**: 26 events
- **Security**: 12 events
- **Powershell**: 43 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
