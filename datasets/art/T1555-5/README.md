# T1555-5: Credentials from Password Stores

**MITRE ATT&CK:** [T1555](https://attack.mitre.org/techniques/T1555)
**Technique:** Credentials from Password Stores
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1555 -TestNumbers 5` — Enumerate credentials from Windows Credential Manager using vaultcmd.exe [Web Credentials]

## Telemetry (91 events)
- **Sysmon**: 42 events
- **Security**: 12 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
