# T1482-1: Domain Trust Discovery

**MITRE ATT&CK:** [T1482](https://attack.mitre.org/techniques/T1482)
**Technique:** Domain Trust Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1482 -TestNumbers 1` — Windows - Discover domain trusts with dsquery

## Telemetry (58 events)
- **Sysmon**: 16 events
- **Security**: 10 events
- **Powershell**: 32 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
