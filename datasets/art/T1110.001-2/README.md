# T1110.001-2: Password Guessing

**MITRE ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001)
**Technique:** Password Guessing
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1110.001 -TestNumbers 2` — Brute Force Credentials of single Active Directory domain user via LDAP against domain controller (NTLM or Kerberos)

## Telemetry (186 events)
- **Sysmon**: 35 events
- **Security**: 118 events
- **Powershell**: 33 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
