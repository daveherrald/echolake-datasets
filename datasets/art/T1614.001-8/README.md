# T1614.001-8: System Language Discovery

**MITRE ATT&CK:** [T1614.001](https://attack.mitre.org/techniques/T1614/001)
**Technique:** System Language Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1614.001 -TestNumbers 8` — Discover System Language by Windows API Query

## Telemetry (70 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
