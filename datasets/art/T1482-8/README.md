# T1482-8: Domain Trust Discovery

**MITRE ATT&CK:** [T1482](https://attack.mitre.org/techniques/T1482)
**Technique:** Domain Trust Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1482 -TestNumbers 8` — TruffleSnout - Listing AD Infrastructure

## Telemetry (80 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
