# T1546-2: Event Triggered Execution

**MITRE ATT&CK:** [T1546](https://attack.mitre.org/techniques/T1546)
**Technique:** Event Triggered Execution
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546 -TestNumbers 2` — HKLM - Persistence using CommandProcessor AutoRun key (With Elevation)

## Telemetry (85 events)
- **Sysmon**: 37 events
- **Security**: 10 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
