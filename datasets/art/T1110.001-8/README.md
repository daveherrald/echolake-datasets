# T1110.001-8: Password Guessing

**MITRE ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001)
**Technique:** Password Guessing
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1110.001 -TestNumbers 8` — ESXi - Brute Force Until Account Lockout

## Telemetry (110 events)
- **Sysmon**: 36 events
- **Security**: 13 events
- **Powershell**: 61 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
