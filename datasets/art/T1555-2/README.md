# T1555-2: Credentials from Password Stores

**MITRE ATT&CK:** [T1555](https://attack.mitre.org/techniques/T1555)
**Technique:** Credentials from Password Stores
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1555 -TestNumbers 2` — Dump credentials from Windows Credential Manager With PowerShell [windows Credentials]

## Telemetry (86 events)
- **Sysmon**: 26 events
- **Security**: 12 events
- **Powershell**: 48 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
