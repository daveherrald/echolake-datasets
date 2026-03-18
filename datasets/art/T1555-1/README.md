# T1555-1: Credentials from Password Stores

**MITRE ATT&CK:** [T1555](https://attack.mitre.org/techniques/T1555)
**Technique:** Credentials from Password Stores
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1555 -TestNumbers 1` — Extract Windows Credential Manager via VBA

## Telemetry (152 events)
- **Sysmon**: 44 events
- **Security**: 16 events
- **Powershell**: 92 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
