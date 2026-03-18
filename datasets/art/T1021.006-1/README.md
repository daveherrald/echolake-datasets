# T1021.006-1: Windows Remote Management

**MITRE ATT&CK:** [T1021.006](https://attack.mitre.org/techniques/T1021/006)
**Technique:** Windows Remote Management
**Tactic(s):** lateral-movement
**ART Test:** `Invoke-AtomicTest T1021.006 -TestNumbers 1` — Enable Windows Remote Management

## Telemetry (920 events)
- **Sysmon**: 59 events
- **Security**: 19 events
- **Powershell**: 835 events
- **System**: 7 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
