# T1614-1: System Location Discovery

**MITRE ATT&CK:** [T1614](https://attack.mitre.org/techniques/T1614)
**Technique:** System Location Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1614 -TestNumbers 1` — Get geolocation info through IP-Lookup services using curl Windows

## Telemetry (67 events)
- **Sysmon**: 21 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
