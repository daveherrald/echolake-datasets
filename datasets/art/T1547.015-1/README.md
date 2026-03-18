# T1547.015-1: Login Items

**MITRE ATT&CK:** [T1547.015](https://attack.mitre.org/techniques/T1547/015)
**Technique:** Login Items
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.015 -TestNumbers 1` — Persistence by modifying Windows Terminal profile

## Telemetry (120 events)
- **Sysmon**: 51 events
- **Security**: 13 events
- **Powershell**: 56 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
