# T1482-3: Domain Trust Discovery

**MITRE ATT&CK:** [T1482](https://attack.mitre.org/techniques/T1482)
**Technique:** Domain Trust Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1482 -TestNumbers 3` — Powershell enumerate domains and forests

## Telemetry (120 events)
- **Sysmon**: 46 events
- **Security**: 13 events
- **Powershell**: 61 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
