# T1547.014-2: Active Setup

**MITRE ATT&CK:** [T1547.014](https://attack.mitre.org/techniques/T1547/014)
**Technique:** Active Setup
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.014 -TestNumbers 2` — HKLM - Add malicious StubPath value to existing Active Setup Entry

## Telemetry (104 events)
- **Sysmon**: 51 events
- **Security**: 15 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
