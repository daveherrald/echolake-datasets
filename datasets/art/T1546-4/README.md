# T1546-4: Event Triggered Execution

**MITRE ATT&CK:** [T1546](https://attack.mitre.org/techniques/T1546)
**Technique:** Event Triggered Execution
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546 -TestNumbers 4` — WMI Invoke-CimMethod Start Process

## Telemetry (158 events)
- **Sysmon**: 49 events
- **Security**: 14 events
- **Powershell**: 95 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
