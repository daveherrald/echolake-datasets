# T1003.004-1: LSA Secrets

**MITRE ATT&CK:** [T1003.004](https://attack.mitre.org/techniques/T1003/004)
**Technique:** LSA Secrets
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.004 -TestNumbers 1` — Dumping LSA Secrets

## Telemetry (70 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
