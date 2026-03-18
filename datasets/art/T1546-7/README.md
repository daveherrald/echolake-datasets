# T1546-7: Event Triggered Execution

**MITRE ATT&CK:** [T1546](https://attack.mitre.org/techniques/T1546)
**Technique:** Event Triggered Execution
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546 -TestNumbers 7` — Persistence using automatic execution of custom DLL during RDP session

## Telemetry (74 events)
- **Sysmon**: 27 events
- **Security**: 13 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
