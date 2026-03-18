# T1614.001-2: System Language Discovery

**MITRE ATT&CK:** [T1614.001](https://attack.mitre.org/techniques/T1614/001)
**Technique:** System Language Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1614.001 -TestNumbers 2` — Discover System Language with chcp

## Telemetry (62 events)
- **Sysmon**: 16 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
