# T1649-1: Steal or Forge Authentication Certificates

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649)
**Technique:** Steal or Forge Authentication Certificates
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1649 -TestNumbers 1` — Staging Local Certificates via Export-Certificate

## Telemetry (96 events)
- **Sysmon**: 41 events
- **Security**: 11 events
- **Powershell**: 44 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
