# T1555-3: Credentials from Password Stores

**MITRE ATT&CK:** [T1555](https://attack.mitre.org/techniques/T1555)
**Technique:** Credentials from Password Stores
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1555 -TestNumbers 3` — Dump credentials from Windows Credential Manager With PowerShell [web Credentials]

## Telemetry (89 events)
- **Sysmon**: 27 events
- **Security**: 10 events
- **Powershell**: 52 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
