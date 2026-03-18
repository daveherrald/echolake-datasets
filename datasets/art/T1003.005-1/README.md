# T1003.005-1: Cached Domain Credentials

**MITRE ATT&CK:** [T1003.005](https://attack.mitre.org/techniques/T1003/005)
**Technique:** Cached Domain Credentials
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.005 -TestNumbers 1` — Cached Credential Dump via Cmdkey

## Telemetry (88 events)
- **Sysmon**: 41 events
- **Security**: 12 events
- **Powershell**: 34 events
- **Application**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
