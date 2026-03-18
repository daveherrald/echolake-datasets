# T1547.010-1: Port Monitors

**MITRE ATT&CK:** [T1547.010](https://attack.mitre.org/techniques/T1547/010)
**Technique:** Port Monitors
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.010 -TestNumbers 1` — Add Port Monitor persistence in Registry

## Telemetry (62 events)
- **Sysmon**: 18 events
- **Security**: 12 events
- **Powershell**: 32 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
