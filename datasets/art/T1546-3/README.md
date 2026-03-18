# T1546-3: Event Triggered Execution

**MITRE ATT&CK:** [T1546](https://attack.mitre.org/techniques/T1546)
**Technique:** Event Triggered Execution
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546 -TestNumbers 3` — HKCU - Persistence using CommandProcessor AutoRun key (Without Elevation)

## Telemetry (85 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 39 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
