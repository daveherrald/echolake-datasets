# T1110.003-3: Password Spraying

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003)
**Technique:** Password Spraying
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1110.003 -TestNumbers 3` — Password spray all Active Directory domain users with a single password via LDAP against domain controller (NTLM or Kerberos)

## Telemetry (82 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 46 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
