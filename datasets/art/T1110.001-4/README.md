# T1110.001-4: Password Guessing

**MITRE ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001)
**Technique:** Password Guessing
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1110.001 -TestNumbers 4` — Password Brute User using Kerbrute Tool

## Telemetry (91 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
