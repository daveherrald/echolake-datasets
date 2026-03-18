# T1614.001-7: System Language Discovery

**MITRE ATT&CK:** [T1614.001](https://attack.mitre.org/techniques/T1614/001)
**Technique:** System Language Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1614.001 -TestNumbers 7` — Discover System Language with dism.exe

## Telemetry (79 events)
- **Sysmon**: 27 events
- **Security**: 18 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
