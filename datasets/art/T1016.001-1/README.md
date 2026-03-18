# T1016.001-1: Internet Connection Discovery

**MITRE ATT&CK:** [T1016.001](https://attack.mitre.org/techniques/T1016/001)
**Technique:** Internet Connection Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1016.001 -TestNumbers 1` — Check internet connection using ping Windows

## Telemetry (80 events)
- **Sysmon**: 34 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
