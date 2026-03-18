# T1137.002-1: Office Test

**MITRE ATT&CK:** [T1137.002](https://attack.mitre.org/techniques/T1137/002)
**Technique:** Office Test
**Tactic(s):** persistence
**ART Test:** `Invoke-AtomicTest T1137.002 -TestNumbers 1` — Office Application Startup Test Persistence (HKCU)

## Telemetry (115 events)
- **Sysmon**: 46 events
- **Security**: 10 events
- **Powershell**: 59 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
