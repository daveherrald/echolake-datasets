# T1555-8: Credentials from Password Stores

**MITRE ATT&CK:** [T1555](https://attack.mitre.org/techniques/T1555)
**Technique:** Credentials from Password Stores
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1555 -TestNumbers 8` — WinPwn - Loot local Credentials - Decrypt Teamviewer Passwords

## Telemetry (99 events)
- **Sysmon**: 38 events
- **Security**: 10 events
- **Powershell**: 51 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
