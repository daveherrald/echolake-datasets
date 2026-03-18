# T1482-2: Domain Trust Discovery

**MITRE ATT&CK:** [T1482](https://attack.mitre.org/techniques/T1482)
**Technique:** Domain Trust Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1482 -TestNumbers 2` — Windows - Discover domain trusts with nltest

## Telemetry (62 events)
- **Sysmon**: 18 events
- **Security**: 14 events
- **Powershell**: 30 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
