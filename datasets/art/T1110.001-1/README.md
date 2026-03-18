# T1110.001-1: Password Guessing

**MITRE ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001)
**Technique:** Password Guessing
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1110.001 -TestNumbers 1` — Brute Force Credentials of single Active Directory domain users via SMB

## Telemetry (77 events)
- **Sysmon**: 23 events
- **Security**: 20 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
