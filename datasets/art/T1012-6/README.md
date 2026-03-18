# T1012-6: Query Registry

**MITRE ATT&CK:** [T1012](https://attack.mitre.org/techniques/T1012)
**Technique:** Query Registry
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1012 -TestNumbers 6` — Inspect SystemStartOptions Value in Registry

## Telemetry (91 events)
- **Sysmon**: 37 events
- **Security**: 12 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
