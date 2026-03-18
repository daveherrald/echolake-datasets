# T1124-6: System Time Discovery

**MITRE ATT&CK:** [T1124](https://attack.mitre.org/techniques/T1124)
**Technique:** System Time Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1124 -TestNumbers 6` — Discover System Time Zone via Registry

## Telemetry (67 events)
- **Sysmon**: 21 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
